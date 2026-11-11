// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Sockaddr is a socket address read from a target's memory.
type Sockaddr struct {
	Family uint16
	// Inet is the AF_INET or AF_INET6 address, IPv4-mapped IPv6
	// addresses unmapped.
	Inet netip.AddrPort
	// Path is an AF_UNIX pathname, as given (not resolved).
	Path string
	// Abstract is set for an AF_UNIX abstract address, Name.
	Abstract bool
	Name     string
}

// sockaddrMax is sizeof(struct sockaddr_storage): the kernel refuses
// longer addresses with EINVAL.
const sockaddrMax = 128

// ParseSockaddr reads a struct sockaddr of len(b) bytes. ok is false for
// an address the kernel refuses (too short) or ignores (unnamed AF_UNIX,
// AF_UNSPEC): the syscall fails or does not reach a peer by address.
// Families other than AF_INET, AF_INET6 and AF_UNIX are returned with
// their family only.
func ParseSockaddr(b []byte) (sa Sockaddr, ok bool) {
	if len(b) < 2 {
		return Sockaddr{}, false
	}
	sa.Family = binary.NativeEndian.Uint16(b)
	switch sa.Family {
	case unix.AF_INET:
		if len(b) < unix.SizeofSockaddrInet4 {
			return sa, false
		}
		port := binary.BigEndian.Uint16(b[2:])
		sa.Inet = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port)
	case unix.AF_INET6:
		// The kernel accepts the RFC 2133 size, without the scope id.
		if len(b) < 24 {
			return sa, false
		}
		port := binary.BigEndian.Uint16(b[2:])
		sa.Inet = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])).Unmap(), port)
	case unix.AF_UNIX:
		p := b[2:]
		if len(p) == 0 {
			return sa, false
		}
		if p[0] == 0 {
			sa.Abstract, sa.Name = true, string(p[1:])
			return sa, true
		}
		if i := strings.IndexByte(string(p), 0); i >= 0 {
			p = p[:i]
		}
		sa.Path = string(p)
	case unix.AF_UNSPEC:
		// udp_sendmsg and raw_sendmsg of AF_INET sockets read it as
		// AF_INET: Inet holds that reading, for the caller to use.
		if len(b) >= unix.SizeofSockaddrInet4 {
			port := binary.BigEndian.Uint16(b[2:])
			sa.Inet = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port)
		}
		return sa, false
	}
	return sa, true
}

// ReadSockaddr reads the struct sockaddr of size bytes at addr in the
// target's memory. Like the kernel, it fails with EINVAL when size is
// too large and EFAULT when the memory cannot be read.
func ReadSockaddr(pid uint32, addr, size uint64) (Sockaddr, bool, error) {
	if size > sockaddrMax {
		return Sockaddr{}, false, unix.EINVAL
	}
	b, err := readMem(pid, addr, int(size))
	if err != nil {
		return Sockaddr{}, false, err
	}
	sa, ok := ParseSockaddr(b)
	return sa, ok, nil
}

// MsgName is the destination of a struct msghdr: msg_name and
// msg_namelen.
type MsgName struct {
	Addr uint64
	Len  uint64
}

// Struct sizes on 64-bit architectures.
const (
	sizeofMsghdr  = 56
	sizeofMmsghdr = 64
	// UIOMaxIOV bounds sendmmsg's vlen (the kernel's UIO_MAXIOV).
	UIOMaxIOV = 1024
)

// ReadMsgNames reads the msg_name and msg_namelen fields of count struct
// msghdr (mmsg false) or struct mmsghdr (mmsg true) at addr in the target's
// memory. It fails with EFAULT when the memory cannot be read.
func ReadMsgNames(pid uint32, addr uint64, count int, mmsg bool) ([]MsgName, error) {
	stride := sizeofMsghdr
	if mmsg {
		stride = sizeofMmsghdr
	}
	if count <= 0 {
		return nil, nil
	}
	// The last one only needs its first 16 bytes.
	b, err := readMem(pid, addr, stride*(count-1)+16)
	if err != nil {
		return nil, err
	}
	out := make([]MsgName, count)
	for i := range out {
		h := b[i*stride:]
		out[i] = MsgName{Addr: binary.NativeEndian.Uint64(h), Len: uint64(binary.NativeEndian.Uint32(h[8:]))}
	}
	return out, nil
}

// readMem reads size bytes at addr in the target's memory, or fails with
// EFAULT.
func readMem(pid uint32, addr uint64, size int) ([]byte, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, size)
	if n, _ := f.ReadAt(b, int64(addr)); n != size {
		return nil, unix.EFAULT
	}
	return b, nil
}

// SocketInfo describes a socket of a target.
type SocketInfo struct {
	Domain, Type, Protocol int
	// Peer is the address an AF_INET or AF_INET6 socket is connected
	// to; not valid otherwise.
	Peer netip.AddrPort
	// Connecting: a TCP socket whose connect is in progress (SYN sent,
	// non-blocking), with no Peer yet.
	Connecting bool
	// Listening: a TCP socket listening, with no Peer: connect fails on
	// it with EISCONN.
	Listening bool
	// Netns is the cookie of the network namespace the socket was made
	// in (SO_NETNS_COOKIE), which it keeps whatever process holds it; 0
	// before Linux 5.14.
	Netns uint64
}

// soNetnsCookie is SO_NETNS_COOKIE (asm-generic: amd64, arm64).
const soNetnsCookie = 71

// TCP states (include/net/tcp_states.h): TCP_SYN_SENT while a socket
// connects, TCP_LISTEN once it listens.
const (
	tcpSynSent = 2
	tcpListen  = 10
)

// SocketNetns returns the cookie of socket fd's network namespace, 0
// when the kernel has none (ENOPROTOOPT, before Linux 5.14).
func SocketNetns(fd int) (uint64, error) {
	c, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, soNetnsCookie)
	if errors.Is(err, unix.ENOPROTOOPT) {
		return 0, nil
	}
	return c, err
}

// Netns returns the cookie of the calling thread's network namespace,
// through a socket made for it; 0 before Linux 5.14.
func Netns() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	return SocketNetns(fd)
}

// GetFD returns a copy of fd of thread tid (pidfd_getfd, which needs
// ptrace access to tid): the same open file description.
func GetFD(tid int, fd int) (int, error) {
	pidfd, err := unix.PidfdOpen(tid, unix.PIDFD_THREAD)
	if err == unix.EINVAL {
		// Before Linux 6.9: the thread group, which shares the fd
		// table but for unshare(CLONE_FILES).
		pidfd, err = unix.PidfdOpen(Tgid(tid), 0)
	}
	if err != nil {
		return -1, err
	}
	defer unix.Close(pidfd)
	return unix.PidfdGetfd(pidfd, fd, 0)
}

// WriteMem writes b at addr in the memory of pid, with
// process_vm_writev: unlike /proc/pid/mem, it does not write through
// read-only mappings.
func WriteMem(pid uint32, addr uint64, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	local := []unix.Iovec{{Base: &b[0]}}
	local[0].SetLen(len(b))
	remote := []unix.RemoteIovec{{Base: uintptr(addr), Len: len(b)}}
	n, err := unix.ProcessVMWritev(int(pid), local, remote, 0)
	if err != nil {
		return err
	}
	if n != len(b) {
		return unix.EFAULT
	}
	return nil
}

// ReadMem reads size bytes at addr in the memory of pid.
func ReadMem(pid uint32, addr uint64, size int) ([]byte, error) {
	return readMem(pid, addr, size)
}

// Socket returns what socket fd of thread tid is, through a copy of the
// fd (pidfd_getfd, which needs ptrace access to tid).
func Socket(tid int, fd int) (SocketInfo, error) {
	s, err := GetFD(tid, fd)
	if err != nil {
		return SocketInfo{}, err
	}
	defer unix.Close(s)
	var si SocketInfo
	for _, o := range []struct {
		opt int
		v   *int
	}{{unix.SO_DOMAIN, &si.Domain}, {unix.SO_TYPE, &si.Type}, {unix.SO_PROTOCOL, &si.Protocol}} {
		if *o.v, err = unix.GetsockoptInt(s, unix.SOL_SOCKET, o.opt); err != nil {
			return SocketInfo{}, err
		}
	}
	if si.Domain == unix.AF_INET || si.Domain == unix.AF_INET6 {
		switch sa := sockname(unix.Getpeername(s)).(type) {
		case *unix.SockaddrInet4:
			si.Peer = netip.AddrPortFrom(netip.AddrFrom4(sa.Addr), uint16(sa.Port))
		case *unix.SockaddrInet6:
			si.Peer = netip.AddrPortFrom(netip.AddrFrom16(sa.Addr).Unmap(), uint16(sa.Port))
		}
		if si.Type == unix.SOCK_STREAM && !si.Peer.IsValid() {
			if ti, err := unix.GetsockoptTCPInfo(s, unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				si.Connecting = ti.State == tcpSynSent
				si.Listening = ti.State == tcpListen
			}
		}
	}
	if si.Netns, err = SocketNetns(s); err != nil {
		return SocketInfo{}, err
	}
	return si, nil
}

// sockname drops the error of Getpeername (ENOTCONN).
func sockname(sa unix.Sockaddr, err error) unix.Sockaddr {
	if err != nil {
		return nil
	}
	return sa
}

// ReadMsgData reads the first buffer (iovec) of count struct msghdr (mmsg
// false) or struct mmsghdr (mmsg true) at addr in the target's memory, at
// most max bytes of each. A message whose buffer cannot be read is left
// out.
func ReadMsgData(pid uint32, addr uint64, count int, mmsg bool, max int) [][]byte {
	stride := sizeofMsghdr
	if mmsg {
		stride = sizeofMmsghdr
	}
	if count <= 0 {
		return nil
	}
	// msg_iov and msg_iovlen are at 16 and 24.
	b, err := readMem(pid, addr, stride*(count-1)+32)
	if err != nil {
		return nil
	}
	var out [][]byte
	for i := range count {
		h := b[i*stride:]
		iov, iovlen := binary.NativeEndian.Uint64(h[16:]), binary.NativeEndian.Uint64(h[24:])
		if iov == 0 || iovlen == 0 {
			continue
		}
		if d := ReadBuf(pid, iov, max); d != nil {
			out = append(out, d)
		}
	}
	return out
}

// ReadBuf reads the buffer of struct iovec at addr in the target's memory,
// at most max bytes of it; nil when it cannot be read.
func ReadBuf(pid uint32, iovec uint64, max int) []byte {
	v, err := readMem(pid, iovec, 16)
	if err != nil {
		return nil
	}
	return ReadData(pid, binary.NativeEndian.Uint64(v), int(min(binary.NativeEndian.Uint64(v[8:]), uint64(max))))
}

// ReadData reads size bytes at addr in the target's memory; nil when it
// cannot be read.
func ReadData(pid uint32, addr uint64, size int) []byte {
	if addr == 0 || size <= 0 {
		return nil
	}
	b, err := readMem(pid, addr, size)
	if err != nil {
		return nil
	}
	return b
}
