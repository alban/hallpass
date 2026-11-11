// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// DNS redirect (Config.DNSForward). An allowed connect, or datagram send
// with an address, to a name server is done by the monitor on a copy of
// the workload's socket (pidfd_getfd: the same open file description),
// to the forwarder's listener instead. The replies come from the
// listener: a receive asking for the source (recvfrom with an address,
// recvmsg) is emulated on the copy, and the source rewritten to the
// server, as resolvers check it (glibc, musl). Go's resolver reads its
// connected socket with read: no source to fix.

// redirectPoll bounds a blocking receive's wait between checks that the
// target still waits (IDValid).
const redirectPoll = 200 * time.Millisecond

// maxRedirected bounds the sockets remembered as redirected. Past it,
// the oldest is forgotten: its replies keep the listener as their
// source, which resolvers drop (DNS fails on that socket, nothing more).
const maxRedirected = 4096

// redirectSet are the sockets redirected to a forwarder: inode, and
// SO_COOKIE, as an inode is reused once its socket is closed.
type redirectSet struct {
	mu     sync.Mutex
	cookie map[uint64]uint64
	order  [][2]uint64 // inode, cookie; oldest first
}

func (s *redirectSet) add(ino, cookie uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cookie == nil {
		s.cookie = map[uint64]uint64{}
	}
	if c, ok := s.cookie[ino]; ok && c == cookie {
		return
	}
	s.cookie[ino] = cookie
	s.order = append(s.order, [2]uint64{ino, cookie})
	for len(s.order) > maxRedirected {
		if s.cookie[s.order[0][0]] == s.order[0][1] {
			delete(s.cookie, s.order[0][0])
		}
		s.order = s.order[1:]
	}
}

// has reports whether a socket of inode ino may be redirected.
func (s *redirectSet) has(ino uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.cookie[ino]
	return ok
}

// is reports whether the socket of inode ino and cookie was redirected;
// an older socket of the inode is forgotten.
func (s *redirectSet) is(ino, cookie uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.cookie[ino]
	if ok && c != cookie {
		delete(s.cookie, ino)
	}
	return ok && c == cookie
}

// sockInode returns the inode of socket fd of tid, from /proc: 0 when fd
// is no socket.
func sockInode(tid uint32, fd int) uint64 {
	s, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", tid, fd))
	if err != nil || !strings.HasPrefix(s, "socket:[") {
		return 0
	}
	ino, _ := strconv.ParseUint(strings.TrimSuffix(s[len("socket:["):], "]"), 10, 64)
	return ino
}

// fwdSockaddr returns the forwarder's listener as a sockaddr for a socket
// of domain.
func fwdSockaddr(domain int, ap netip.AddrPort) (unix.Sockaddr, bool) {
	a := ap.Addr()
	switch {
	case domain == unix.AF_INET && a.Is4():
		return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: a.As4()}, true
	case domain == unix.AF_INET6:
		// A v4 listener through a v4-mapped address (fails with
		// IPV6_V6ONLY, as the workload's own connect would).
		return &unix.SockaddrInet6{Port: int(ap.Port()), Addr: a.As16()}, true
	}
	return nil, false
}

// redirectDNS does the allowed connect or sendto n, to a name server
// with a forwarder listener, to the listener instead, and reports true
// once answered. False: nothing answered (not a server, another network
// namespace, sendmsg...): the syscall is continued as usual.
func (m *Monitor) redirectDNS(l *listener, n seccomp.Notif, sc seccomp.Rule, op rules.Op, items []item, why []Reason) bool {
	if m.dnsFwd == nil || len(items) != 1 || items[0].obj.Inet == nil {
		return false
	}
	if sc.Name != "connect" && sc.Name != "sendto" {
		return false
	}
	dst := items[0].obj.Inet.Addr
	fwd, ok := m.dnsFwd[dst.Addr().Unmap()]
	if !ok || dst.Port() != 53 {
		return false
	}
	r, ok := l.n.(fdReplacer)
	if !ok {
		return false
	}
	fd := int(int32(n.Args[0]))
	cp, err := procfs.GetFD(int(n.PID), fd)
	if err != nil {
		return false
	}
	defer unix.Close(cp)
	domain, err := unix.GetsockoptInt(cp, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return false
	}
	typ, err := unix.GetsockoptInt(cp, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || (sc.Name == "sendto" && typ != unix.SOCK_DGRAM) {
		// A TCP send's address is a fast open: to the server.
		return false
	}
	if c, err := procfs.SocketNetns(cp); err != nil || m.netns == 0 || c != m.netns {
		// The listener is in the session's network namespace only.
		return false
	}
	sa, ok := fwdSockaddr(domain, fwd)
	if !ok {
		return false
	}
	var st unix.Stat_t
	cookie, err := unix.GetsockoptUint64(cp, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || unix.Fstat(cp, &st) != nil {
		return false
	}
	m.redirected.add(st.Ino, cookie)
	answer := func(v int64, err error) {
		var e unix.Errno
		switch {
		case err == nil:
			_ = r.Return(n.ID, v)
		case errors.As(err, &e):
			_ = l.n.Deny(n.ID, int32(e))
		default:
			_ = l.n.Deny(n.ID, int32(unix.EIO))
		}
	}
	m.report(n, sc.Name, op, objects(items), true, why)
	switch sc.Name {
	case "connect":
		// The copy shares O_NONBLOCK: a non-blocking TCP connect
		// answers EINPROGRESS, as the workload's own would.
		answer(0, unix.Connect(cp, sa))
	case "sendto":
		if n.Args[2] > 65535 {
			_ = l.n.Deny(n.ID, int32(unix.EMSGSIZE))
			return true
		}
		b, err := procfs.ReadMem(n.PID, n.Args[1], int(n.Args[2]))
		if err != nil {
			_ = l.n.Deny(n.ID, int32(unix.EFAULT))
			return true
		}
		if !l.n.IDValid(n.ID) {
			return true
		}
		err = unix.Sendto(cp, b, int(n.Args[3])|unix.MSG_DONTWAIT, sa)
		answer(int64(len(b)), err)
	}
	return true
}

// recvFrom answers recvfrom n, with an address, or recvmsg n, on a
// socket redirected to the forwarder: received on a copy of the socket,
// the data and the source (the server for the listener's replies) are
// written in the target's memory. Other receives are continued at once.
// A receive that would block waits in its own goroutine (ask); a signal
// the target catches does not interrupt it.
func (m *Monitor) recvFrom(l *listener, n seccomp.Notif, sc seccomp.Rule) (ask func()) {
	cont := func() {
		if err := l.n.Continue(n.ID); err != nil && !errors.Is(err, unix.ENOENT) {
			m.warn("continue: " + err.Error())
		}
	}
	fd := int(int32(n.Args[0]))
	if m.dnsFwd == nil {
		cont()
		return nil
	}
	if !m.redirected.has(sockInode(n.PID, fd)) {
		cont()
		return nil
	}
	r, ok := l.n.(fdReplacer)
	if !ok {
		cont()
		return nil
	}
	cp, err := procfs.GetFD(int(n.PID), fd)
	if err != nil {
		cont()
		return nil
	}
	var st unix.Stat_t
	cookie, err := unix.GetsockoptUint64(cp, unix.SOL_SOCKET, unix.SO_COOKIE)
	if err != nil || unix.Fstat(cp, &st) != nil || !m.redirected.is(st.Ino, cookie) {
		// Closed and its inode reused since, or fd replaced.
		unix.Close(cp)
		cont()
		return nil
	}
	if done := m.recvOnce(l, r, n, sc, cp); done {
		unix.Close(cp)
		return nil
	}
	// Blocking, nothing yet: wait for data, the socket's SO_RCVTIMEO or
	// the target's death, in a goroutine.
	return func() {
		defer unix.Close(cp)
		var deadline time.Time
		if tv, err := unix.GetsockoptTimeval(cp, unix.SOL_SOCKET, unix.SO_RCVTIMEO); err == nil && (tv.Sec != 0 || tv.Usec != 0) {
			deadline = time.Now().Add(time.Duration(tv.Nano()))
		}
		for {
			wait := redirectPoll
			if !deadline.IsZero() {
				left := time.Until(deadline)
				if left <= 0 {
					_ = l.n.Deny(n.ID, int32(unix.EAGAIN))
					return
				}
				wait = min(wait, left)
			}
			pfd := []unix.PollFd{{Fd: int32(cp), Events: unix.POLLIN}}
			if _, err := unix.Poll(pfd, int(wait.Milliseconds())+1); err != nil && !errors.Is(err, unix.EINTR) {
				_ = l.n.Deny(n.ID, int32(errnoOf(err)))
				return
			}
			if !l.n.IDValid(n.ID) {
				return
			}
			if pfd[0].Revents != 0 && m.recvOnce(l, r, n, sc, cp) {
				return
			}
		}
	}
}

// recvArgs are where a recvfrom or recvmsg wants its results, in the
// target's memory.
type recvArgs struct {
	iovs  [][2]uint64 // base, len
	flags int
	// name is the source buffer, nameLen the socklen_t of its size,
	// written back (recvfrom's addrlen, msghdr's msg_namelen).
	name, nameLen uint64
	// recvmsg: the msghdr, its control buffer and size.
	msg, ctl uint64
	ctlLen   int
}

// readRecvArgs reads the arguments of recvfrom or recvmsg n.
func readRecvArgs(n seccomp.Notif, sc seccomp.Rule) (recvArgs, error) {
	if sc.Name == "recvfrom" {
		return recvArgs{iovs: [][2]uint64{{n.Args[1], n.Args[2]}}, flags: int(n.Args[3]), name: n.Args[4], nameLen: n.Args[5]}, nil
	}
	h, err := procfs.ReadMem(n.PID, n.Args[1], 56)
	if err != nil {
		return recvArgs{}, err
	}
	u := func(off int) uint64 { return binary.NativeEndian.Uint64(h[off:]) }
	a := recvArgs{flags: int(n.Args[2]), name: u(0), nameLen: n.Args[1] + 8, msg: n.Args[1], ctl: u(32), ctlLen: int(min(u(40), 1<<16))}
	if a.ctl == 0 {
		a.ctlLen = 0
	}
	if iovlen := min(int(u(24)), procfs.UIOMaxIOV); iovlen > 0 {
		v, err := procfs.ReadMem(n.PID, u(16), 16*iovlen)
		if err != nil {
			return recvArgs{}, err
		}
		for i := range iovlen {
			a.iovs = append(a.iovs, [2]uint64{binary.NativeEndian.Uint64(v[16*i:]), binary.NativeEndian.Uint64(v[16*i+8:])})
		}
	}
	return a, nil
}

// recvOnce receives once, without waiting, on cp for recvfrom or recvmsg
// n, and reports whether n was answered: false when it would block and
// the socket blocks.
func (m *Monitor) recvOnce(l *listener, r fdReplacer, n seccomp.Notif, sc seccomp.Rule, cp int) bool {
	fail := func(e unix.Errno) bool {
		_ = l.n.Deny(n.ID, int32(e))
		return true
	}
	a, err := readRecvArgs(n, sc)
	if err != nil {
		return fail(unix.EFAULT)
	}
	size := 0
	for _, v := range a.iovs {
		size += int(v[1])
	}
	size = min(size, 1<<20)
	buf := make([]byte, size)
	var oob []byte
	if a.ctlLen > 0 {
		oob = make([]byte, a.ctlLen)
	}
	got, oobn, rflags, from, err := unix.Recvmsg(cp, buf, oob, a.flags|unix.MSG_DONTWAIT)
	if errors.Is(err, unix.EAGAIN) {
		fl, ferr := unix.FcntlInt(uintptr(cp), unix.F_GETFL, 0)
		if a.flags&unix.MSG_DONTWAIT != 0 || ferr != nil || fl&unix.O_NONBLOCK != 0 {
			return fail(unix.EAGAIN)
		}
		return false
	}
	if err != nil {
		return fail(errnoOf(err))
	}
	if !l.n.IDValid(n.ID) {
		// Dequeued, and the target is gone: lost, as with a kill.
		return true
	}
	data := buf[:min(got, size)]
	for _, v := range a.iovs {
		if len(data) == 0 {
			break
		}
		k := min(len(data), int(v[1]))
		if err := procfs.WriteMem(n.PID, v[0], data[:k]); err != nil {
			return fail(unix.EFAULT)
		}
		data = data[k:]
	}
	if a.name != 0 && a.nameLen != 0 {
		lb, err := procfs.ReadMem(n.PID, a.nameLen, 4)
		if err != nil {
			return fail(unix.EFAULT)
		}
		room := int(binary.NativeEndian.Uint32(lb))
		sa := m.rawSource(from)
		if len(sa) > 0 && room > 0 {
			if err := procfs.WriteMem(n.PID, a.name, sa[:min(room, len(sa))]); err != nil {
				return fail(unix.EFAULT)
			}
		}
		binary.NativeEndian.PutUint32(lb, uint32(len(sa)))
		if err := procfs.WriteMem(n.PID, a.nameLen, lb); err != nil {
			return fail(unix.EFAULT)
		}
	}
	if a.msg != 0 {
		// Inet control messages carry no descriptor: copied as they are.
		if oobn > 0 {
			if err := procfs.WriteMem(n.PID, a.ctl, oob[:oobn]); err != nil {
				return fail(unix.EFAULT)
			}
		}
		var b [8]byte
		binary.NativeEndian.PutUint64(b[:], uint64(oobn))
		if err := procfs.WriteMem(n.PID, a.msg+40, b[:]); err != nil {
			return fail(unix.EFAULT)
		}
		binary.NativeEndian.PutUint32(b[:4], uint32(rflags))
		if err := procfs.WriteMem(n.PID, a.msg+48, b[:4]); err != nil {
			return fail(unix.EFAULT)
		}
	}
	_ = r.Return(n.ID, int64(got))
	return true
}

// isForwarder reports whether ap is a forwarder's listener: the peer of
// a socket redirected to it.
func (m *Monitor) isForwarder(ap netip.AddrPort) bool {
	_, ok := m.dnsSrc[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]
	return ok
}

// rawSource returns from as the bytes of a struct sockaddr, with a
// forwarder listener replaced by its server, in from's family.
func (m *Monitor) rawSource(from unix.Sockaddr) []byte {
	var ap netip.AddrPort
	six := false
	switch sa := from.(type) {
	case *unix.SockaddrInet4:
		ap = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port))
	case *unix.SockaddrInet6:
		ap, six = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), uint16(sa.Port)), true
	default:
		return nil
	}
	if s, ok := m.dnsSrc[netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())]; ok {
		ap = netip.AddrPortFrom(s, 53)
	}
	if !six {
		b := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], ap.Port())
		a := ap.Addr().Unmap().As4()
		copy(b[4:], a[:])
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As16()
	copy(b[8:], a[:])
	return b
}
