// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package procfs

import (
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func rawInet4(ip [4]byte, port uint16) []byte {
	b := make([]byte, unix.SizeofSockaddrInet4)
	binary.NativeEndian.PutUint16(b, unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:], port)
	copy(b[4:], ip[:])
	return b
}

func rawInet6(ip netip.Addr, port uint16, n int) []byte {
	b := make([]byte, n)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], port)
	a := ip.As16()
	copy(b[8:], a[:])
	return b
}

func rawUnix(path string, n int) []byte {
	b := make([]byte, n)
	binary.NativeEndian.PutUint16(b, unix.AF_UNIX)
	copy(b[2:], path)
	return b
}

func TestParseSockaddr(t *testing.T) {
	ap := netip.MustParseAddrPort
	for _, tc := range []struct {
		name string
		b    []byte
		want Sockaddr
		ok   bool
	}{
		{"inet", rawInet4([4]byte{1, 2, 3, 4}, 443), Sockaddr{Family: unix.AF_INET, Inet: ap("1.2.3.4:443")}, true},
		{"inet short", rawInet4([4]byte{1, 2, 3, 4}, 443)[:8], Sockaddr{Family: unix.AF_INET}, false},
		{"inet6", rawInet6(netip.MustParseAddr("2001:db8::1"), 53, 28), Sockaddr{Family: unix.AF_INET6, Inet: ap("[2001:db8::1]:53")}, true},
		{"inet6 rfc2133", rawInet6(netip.MustParseAddr("::1"), 80, 24), Sockaddr{Family: unix.AF_INET6, Inet: ap("[::1]:80")}, true},
		{"inet6 short", rawInet6(netip.MustParseAddr("::1"), 80, 20), Sockaddr{Family: unix.AF_INET6}, false},
		{"mapped", rawInet6(netip.MustParseAddr("::ffff:127.0.0.1"), 8080, 28), Sockaddr{Family: unix.AF_INET6, Inet: ap("127.0.0.1:8080")}, true},
		{"unix path", rawUnix("/run/x.sock", 110), Sockaddr{Family: unix.AF_UNIX, Path: "/run/x.sock"}, true},
		{"unix path no nul", rawUnix("rel", 5), Sockaddr{Family: unix.AF_UNIX, Path: "rel"}, true},
		{"abstract", rawUnix("\x00name", 7), Sockaddr{Family: unix.AF_UNIX, Abstract: true, Name: "name"}, true},
		{"abstract with nul", rawUnix("\x00a\x00b", 6), Sockaddr{Family: unix.AF_UNIX, Abstract: true, Name: "a\x00b"}, true},
		{"unnamed", rawUnix("", 2), Sockaddr{Family: unix.AF_UNIX}, false},
		{"unspec", []byte{0, 0, 0, 0}, Sockaddr{}, false},
		{"unspec as inet", append([]byte{0, 0}, rawInet4([4]byte{1, 2, 3, 4}, 53)[2:]...), Sockaddr{Inet: ap("1.2.3.4:53")}, false},
		{"netlink", []byte{unix.AF_NETLINK, 0, 0, 0}, Sockaddr{Family: unix.AF_NETLINK}, true},
		{"empty", nil, Sockaddr{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseSockaddr(tc.b)
			if got != tc.want || ok != tc.ok {
				t.Errorf("got %+v, %v; want %+v, %v", got, ok, tc.want, tc.ok)
			}
		})
	}
}

// msgSink makes the test's buffers escape to the heap: stack objects move
// when the stack grows, and the reads use raw addresses.
var msgSink []any

// TestReadMsgNames reads msghdrs and a sockaddr from this process.
func TestReadMsgNames(t *testing.T) {
	pid := uint32(os.Getpid())
	sa := rawInet4([4]byte{10, 0, 0, 1}, 53)
	hs := new([3]unix.Mmsghdr)
	h := new(unix.Msghdr)
	msgSink = []any{sa, hs, h}
	defer func() { msgSink = nil }()
	hs[0].Hdr.Name, hs[0].Hdr.Namelen = &sa[0], uint32(len(sa))
	hs[2].Hdr.Name, hs[2].Hdr.Namelen = &sa[0], 3
	names, err := ReadMsgNames(pid, uint64(uintptr(unsafe.Pointer(&hs[0]))), len(hs), true)
	if err != nil {
		t.Fatal(err)
	}
	want := []MsgName{{uint64(uintptr(unsafe.Pointer(&sa[0]))), 16}, {0, 0}, {uint64(uintptr(unsafe.Pointer(&sa[0]))), 3}}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("mmsghdr %d: got %+v, want %+v", i, names[i], want[i])
		}
	}
	got, ok, err := ReadSockaddr(pid, names[0].Addr, names[0].Len)
	if err != nil || !ok || got.Inet != netip.MustParseAddrPort("10.0.0.1:53") {
		t.Errorf("sockaddr: %+v %v %v", got, ok, err)
	}
	h.Name, h.Namelen = &sa[0], 16
	names, err = ReadMsgNames(pid, uint64(uintptr(unsafe.Pointer(h))), 1, false)
	if err != nil || len(names) != 1 || names[0].Len != 16 {
		t.Errorf("msghdr: %+v %v", names, err)
	}
	runtime.KeepAlive(hs)
	runtime.KeepAlive(h)
	runtime.KeepAlive(sa)
	if _, _, err := ReadSockaddr(pid, 8, 16); err != unix.EFAULT {
		t.Errorf("bad pointer: %v, want EFAULT", err)
	}
	if _, _, err := ReadSockaddr(pid, names[0].Addr, 129); err != unix.EINVAL {
		t.Errorf("long sockaddr: %v, want EINVAL", err)
	}
}

func TestSocket(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	got, err := Socket(unix.Gettid(), fd)
	if err != nil {
		t.Fatal(err)
	}
	if want := (SocketInfo{unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
