// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package netdiag lists listening sockets with NETLINK_SOCK_DIAG, and
// finds which processes hold them, so lite mode can tell a listener
// started inside the sandbox from one outside. It is racy: a socket can
// change hands between the dump and the connect.
package netdiag

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// TCPListener is a listening TCP socket.
type TCPListener struct {
	Addr   netip.AddrPort // local address, unmapped
	V6Only bool
	Inode  uint64
}

// UnixSocket is a bound unix socket.
type UnixSocket struct {
	Inode    uint64
	Type     int // unix.SOCK_STREAM, ...
	Listen   bool
	Abstract bool
	Name     string // abstract name, without the leading NUL
	Path     string // bound path as given to bind(2)
	VFSDev   uint64 // superblock of the socket file, in stat(2)'s encoding
	VFSIno   uint64
}

const (
	sockDiagByFamily = 20
	tcpListen        = 10

	inetDiagSkV6Only = 11

	unixDiagName  = 0
	unixDiagVFS   = 1
	udiagShowName = 0x1
	udiagShowVFS  = 0x2
)

// Diag is a sock_diag socket of one network namespace.
type Diag struct {
	fd int
}

// Open returns a sock_diag socket in the network namespace of pid: this
// process's if it is the same, else entered with setns(2), which needs
// CAP_SYS_ADMIN over it.
func Open(pid int) (*Diag, error) {
	same, err := sameNetns(pid)
	if err != nil {
		return nil, err
	}
	if same {
		return open()
	}
	ns, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(ns)
	self, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(self)
	// The socket keeps the namespace it was created in.
	runtime.LockOSThread()
	if err := unix.Setns(ns, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("enter the network namespace of %d: %w", pid, err)
	}
	d, err := open()
	if unix.Setns(self, unix.CLONE_NEWNET) == nil {
		// Otherwise the thread stays locked and exits with the
		// goroutine.
		runtime.UnlockOSThread()
	}
	return d, err
}

func sameNetns(pid int) (bool, error) {
	var a, b unix.Stat_t
	if err := unix.Stat("/proc/thread-self/ns/net", &a); err != nil {
		return false, err
	}
	if err := unix.Stat(fmt.Sprintf("/proc/%d/ns/net", pid), &b); err != nil {
		return false, err
	}
	return a.Dev == b.Dev && a.Ino == b.Ino, nil
}

func open() (*Diag, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	return &Diag{fd: fd}, nil
}

// Close closes d.
func (d *Diag) Close() error { return unix.Close(d.fd) }

// Supported returns an error if this kernel cannot dump TCP or unix
// sockets: without CONFIG_INET_DIAG or CONFIG_UNIX_DIAG, the dumps fail
// with ENOENT.
func Supported() error {
	d, err := open()
	if err != nil {
		return err
	}
	defer d.Close()
	if _, err := d.TCPListeners(1); err != nil {
		return fmt.Errorf("sock_diag of TCP sockets: %w", err)
	}
	if _, err := d.UnixSockets(); err != nil {
		return fmt.Errorf("sock_diag of unix sockets: %w", err)
	}
	return nil
}

// TCPListeners returns the TCP listeners, IPv4 and IPv6, on port (any
// port if 0).
func (d *Diag) TCPListeners(port uint16) ([]TCPListener, error) {
	var out []TCPListener
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		// struct inet_diag_req_v2; the socket id is ignored by dumps.
		req := make([]byte, 56)
		req[0], req[1] = fam, unix.IPPROTO_TCP
		binary.NativeEndian.PutUint32(req[4:], 1<<tcpListen)
		err := d.dump(req, func(msg []byte) error {
			// struct inet_diag_msg: 72 bytes, then attributes.
			if len(msg) < 72 {
				return errors.New("short inet_diag_msg")
			}
			sport := binary.BigEndian.Uint16(msg[4:])
			if port != 0 && sport != port {
				return nil
			}
			var addr netip.Addr
			if msg[0] == unix.AF_INET {
				addr = netip.AddrFrom4([4]byte(msg[8:12]))
			} else {
				addr = netip.AddrFrom16([16]byte(msg[8:24])).Unmap()
			}
			l := TCPListener{
				Addr:  netip.AddrPortFrom(addr, sport),
				Inode: uint64(binary.NativeEndian.Uint32(msg[68:])),
			}
			attrs(msg[72:], func(typ uint16, v []byte) {
				if typ == inetDiagSkV6Only && len(v) >= 1 {
					l.V6Only = v[0] != 0
				}
			})
			out = append(out, l)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UnixSockets returns the bound unix sockets.
func (d *Diag) UnixSockets() ([]UnixSocket, error) {
	// struct unix_diag_req
	req := make([]byte, 24)
	req[0] = unix.AF_UNIX
	binary.NativeEndian.PutUint32(req[4:], 0xffffffff)
	binary.NativeEndian.PutUint32(req[12:], udiagShowName|udiagShowVFS)
	var out []UnixSocket
	err := d.dump(req, func(msg []byte) error {
		// struct unix_diag_msg: 16 bytes, then attributes.
		if len(msg) < 16 {
			return errors.New("short unix_diag_msg")
		}
		s := UnixSocket{
			Type:   int(msg[1]),
			Listen: msg[2] == tcpListen,
			Inode:  uint64(binary.NativeEndian.Uint32(msg[4:])),
		}
		named := false
		attrs(msg[16:], func(typ uint16, v []byte) {
			switch typ {
			case unixDiagName:
				if len(v) == 0 {
					return
				}
				named = true
				if v[0] == 0 {
					s.Abstract, s.Name = true, string(v[1:])
				} else {
					s.Path, _, _ = strings.Cut(string(v), "\x00")
				}
			case unixDiagVFS:
				if len(v) >= 8 {
					s.VFSIno = uint64(binary.NativeEndian.Uint32(v))
					// The kernel's dev_t: major << 20 | minor.
					kdev := binary.NativeEndian.Uint32(v[4:])
					s.VFSDev = unix.Mkdev(kdev>>20, kdev&0xfffff)
				}
			}
		})
		if named {
			out = append(out, s)
		}
		return nil
	})
	return out, err
}

// SocketFile returns the device and inode of the socket file at path, in
// the form of UnixSocket.VFSDev and VFSIno: the device is the superblock's,
// from pid's mountinfo, which differs from stat(2)'s st_dev on btrfs
// subvolumes.
func SocketFile(pid int, path string) (dev, ino uint64, err error) {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_INO|unix.STATX_MNT_ID, &stx); err != nil {
		return 0, 0, err
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 {
		return 0, 0, errors.New("statx: no mount id")
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return 0, 0, err
	}
	id := strconv.FormatUint(stx.Mnt_id, 10) + " "
	for _, l := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(l, id) {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 3 {
			break
		}
		maj, min, ok := strings.Cut(f[2], ":")
		a, err1 := strconv.ParseUint(maj, 10, 32)
		c, err2 := strconv.ParseUint(min, 10, 32)
		if !ok || err1 != nil || err2 != nil {
			break
		}
		return unix.Mkdev(uint32(a), uint32(c)), stx.Ino, nil
	}
	return 0, 0, fmt.Errorf("mount %d of %s not found", stx.Mnt_id, path)
}
func (d *Diag) dump(req []byte, fn func(msg []byte) error) error {
	const seq = 1
	hdr := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(req))
	binary.NativeEndian.PutUint32(hdr[0:], uint32(unix.NLMSG_HDRLEN+len(req)))
	binary.NativeEndian.PutUint16(hdr[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(hdr[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(hdr[8:], seq)
	if err := unix.Sendto(d.fd, append(hdr, req...), 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 64<<10)
	for {
		n, _, err := unix.Recvfrom(d.fd, buf, 0)
		if err != nil {
			return err
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if e := int32(binary.NativeEndian.Uint32(m.Data)); e != 0 {
						return unix.Errno(-e)
					}
				}
				return nil
			}
			if err := fn(m.Data); err != nil {
				return err
			}
		}
	}
}

// attrs calls fn on each netlink attribute of b.
func attrs(b []byte, fn func(typ uint16, v []byte)) {
	for len(b) >= unix.SizeofRtAttr {
		l := int(binary.NativeEndian.Uint16(b))
		if l < unix.SizeofRtAttr || l > len(b) {
			return
		}
		fn(binary.NativeEndian.Uint16(b[2:])&0x3fff, b[unix.SizeofRtAttr:l])
		l = (l + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1)
		if l > len(b) {
			return
		}
		b = b[l:]
	}
}

// Descendants returns roots and their descendants, from one read of every
// /proc/<pid>/stat. Racy like procfs.Descends.
func Descendants(roots []int) map[int]bool {
	out := map[int]bool{}
	children := map[int][]int{}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + p.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...
		i := strings.LastIndexByte(string(b), ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) < 2 {
			continue
		}
		if ppid, err := strconv.Atoi(f[1]); err == nil {
			children[ppid] = append(children[ppid], pid)
		}
	}
	queue := append([]int(nil), roots...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if pid <= 0 || out[pid] {
			continue
		}
		out[pid] = true
		queue = append(queue, children[pid]...)
	}
	return out
}

// Held returns the socket inodes of want held in the fd tables of the
// processes for which member(pid) is true. It reads every /proc/<pid>/fd
// it may (other users' are skipped).
func Held(want map[uint64]bool, member func(pid int) bool) map[uint64]bool {
	found := map[uint64]bool{}
	if len(want) == 0 {
		return found
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return found
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || !member(pid) {
			continue
		}
		dir := "/proc/" + p.Name() + "/fd/"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			l, err := os.Readlink(dir + fd.Name())
			if err != nil {
				continue
			}
			s, ok := strings.CutPrefix(l, "socket:[")
			if !ok {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(s, "]"), 10, 64)
			if err == nil && want[ino] {
				found[ino] = true
				if len(found) == len(want) {
					return found
				}
			}
		}
	}
	return found
}

// TCPCandidates returns the inodes of the listeners a TCP connection to
// dst would reach, the way the kernel looks them up: those bound to dst's
// address if any, else the wildcard ones (0.0.0.0, or :: unless
// IPV6_V6ONLY for an IPv4 dst). Device bindings are ignored.
func TCPCandidates(ls []TCPListener, dst netip.AddrPort) []uint64 {
	addr := dst.Addr().Unmap()
	var exact, wild []uint64
	for _, l := range ls {
		if l.Addr.Port() != dst.Port() {
			continue
		}
		la := l.Addr.Addr()
		switch {
		case la == addr:
			exact = append(exact, l.Inode)
		case la.IsUnspecified():
			if addr.Is4() && la.Is6() && l.V6Only {
				continue
			}
			if addr.Is6() && la.Is4() {
				continue
			}
			wild = append(wild, l.Inode)
		}
	}
	if len(exact) > 0 {
		return exact
	}
	return wild
}
