// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/alban/hallpass/internal/netdiag"
	"github.com/alban/hallpass/internal/rules"
	"golang.org/x/sys/unix"
)

func netRule(t *testing.T, spec string, v rules.Verdict) rules.Rule {
	t.Helper()
	m, err := rules.ParseNet(spec)
	if err != nil {
		t.Fatal(err)
	}
	return rules.Rule{Ops: rules.OpNet, Verdict: v, Object: m}
}

// sock opens a socket closed with the test.
func sock(t *testing.T, domain, typ int) int {
	t.Helper()
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return fd
}

// keep returns the address of b, kept alive until the test ends.
func (f *fakeNotifier) keep(b []byte) uint64 {
	f.mu.Lock()
	f.alive = append(f.alive, b)
	f.mu.Unlock()
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

func sockaddrInet(ap string) []byte {
	a := netip.MustParseAddrPort(ap)
	if a.Addr().Is4() {
		b := make([]byte, unix.SizeofSockaddrInet4)
		binary.NativeEndian.PutUint16(b, unix.AF_INET)
		binary.BigEndian.PutUint16(b[2:], a.Port())
		ip := a.Addr().As4()
		copy(b[4:], ip[:])
		return b
	}
	b := make([]byte, unix.SizeofSockaddrInet6)
	binary.NativeEndian.PutUint16(b, unix.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], a.Port())
	ip := a.Addr().As16()
	copy(b[8:], ip[:])
	return b
}

// sockaddrUnix is a pathname, or an abstract name if it starts with @.
func sockaddrUnix(name string) []byte {
	b := make([]byte, 2, 2+len(name)+1)
	binary.NativeEndian.PutUint16(b, unix.AF_UNIX)
	if name[0] == '@' {
		return append(append(b, 0), name[1:]...)
	}
	return append(append(b, name...), 0)
}

func (f *fakeNotifier) connect(fd int, sa []byte) uint64 {
	return f.send(unix.SYS_CONNECT, nil, map[int]uint64{0: uint64(fd), 1: f.keep(sa), 2: uint64(len(sa))})
}

func (f *fakeNotifier) sendto(fd int, flags int, sa []byte) uint64 {
	extra := map[int]uint64{0: uint64(fd), 1: 0, 2: 0, 3: uint64(flags), 4: 0, 5: 0}
	if sa != nil {
		extra[4], extra[5] = f.keep(sa), uint64(len(sa))
	}
	return f.send(unix.SYS_SENDTO, nil, extra)
}

// sendmmsg sends one message per sockaddr (nil: none).
func (f *fakeNotifier) sendmmsg(fd int, sas ...[]byte) uint64 {
	hs := make([]unix.Mmsghdr, len(sas))
	for i, sa := range sas {
		if sa != nil {
			f.keep(sa)
			hs[i].Hdr.Name, hs[i].Hdr.Namelen = &sa[0], uint32(len(sa))
		}
	}
	f.mu.Lock()
	f.alive = append(f.alive, hs)
	f.mu.Unlock()
	return f.send(unix.SYS_SENDMMSG, nil, map[int]uint64{0: uint64(fd), 1: uint64(uintptr(unsafe.Pointer(&hs[0]))), 2: uint64(len(hs)), 3: 0})
}

func (f *fakeNotifier) sendmsg(fd int, sa []byte) uint64 {
	h := &unix.Msghdr{}
	if sa != nil {
		f.keep(sa)
		h.Name, h.Namelen = &sa[0], uint32(len(sa))
	}
	f.mu.Lock()
	f.alive = append(f.alive, h)
	f.mu.Unlock()
	return f.send(unix.SYS_SENDMSG, nil, map[int]uint64{0: uint64(fd), 1: uint64(uintptr(unsafe.Pointer(h))), 2: 0})
}

func TestNetInet(t *testing.T) {
	fx := setup(t, nil, false)
	if _, err := fx.m.Apply(rulesDecision(
		netRule(t, "tcp:192.0.2.0/24:443", rules.Allow),
		netRule(t, "198.51.100.1", rules.Deny),
		netRule(t, "udp:[2001:db8::]/32:53", rules.Allow),
	)); err != nil {
		t.Fatal(err)
	}
	tcp, tcp6 := sock(t, unix.AF_INET, unix.SOCK_STREAM), sock(t, unix.AF_INET6, unix.SOCK_STREAM)
	udp, udp6 := sock(t, unix.AF_INET, unix.SOCK_DGRAM), sock(t, unix.AF_INET6, unix.SOCK_DGRAM)
	f := fx.f
	f.expect(t, f.connect(tcp, sockaddrInet("192.0.2.7:443")), 0)
	f.expect(t, f.connect(tcp6, sockaddrInet("[::ffff:192.0.2.7]:443")), 0)
	f.expect(t, f.connect(tcp, sockaddrInet("198.51.100.1:80")), int32(unix.EACCES))
	f.expect(t, f.sendto(udp, 0, sockaddrInet("198.51.100.1:53")), int32(unix.EACCES))
	f.expect(t, f.sendmsg(udp6, sockaddrInet("[2001:db8::1]:53")), 0)
	// A connected socket: no address, nothing to check.
	f.expect(t, f.sendmsg(udp, nil), 0)
	f.expect(t, f.sendmmsg(udp, nil, nil), 0)
	// TCP ignores the address of a send, but for TCP Fast Open.
	f.expect(t, f.sendto(tcp, 0, sockaddrInet("198.51.100.1:80")), 0)
	f.expect(t, f.sendto(tcp, unix.MSG_FASTOPEN, sockaddrInet("198.51.100.1:80")), int32(unix.EACCES))
	// One denied destination denies the whole sendmmsg.
	f.expect(t, f.sendmmsg(udp6, sockaddrInet("[2001:db8::1]:53"), nil, sockaddrInet("[::ffff:198.51.100.1]:53")), int32(unix.EACCES))
	// Disconnecting is no destination.
	f.expect(t, f.connect(udp, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), 0)
	// But udp_sendmsg reads AF_UNSPEC as AF_INET; IPv6 ignores it.
	unspec := sockaddrInet("198.51.100.1:53")
	unspec[0], unspec[1] = 0, 0
	f.expect(t, f.sendto(udp, 0, unspec), int32(unix.EACCES))
	f.expect(t, f.sendto(udp6, 0, append(unspec, make([]byte, 12)...)), 0)
	// Unreadable.
	f.expect(t, f.send(unix.SYS_CONNECT, nil, map[int]uint64{0: uint64(tcp), 1: 8, 2: 16}), int32(unix.EFAULT))

	id := f.connect(tcp6, sockaddrInet("[::ffff:203.0.113.5]:22"))
	req := fx.next(t, opened).Opened
	if o := req.Objects[0].Inet; req.Op != rules.OpConnect || o == nil || o.Proto != unix.IPPROTO_TCP || o.Addr != netip.MustParseAddrPort("203.0.113.5:22") {
		t.Fatalf("request %+v %+v", req, req.Objects[0])
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, id, int32(unix.EACCES))

	id = f.sendto(tcp, unix.MSG_FASTOPEN, sockaddrInet("203.0.113.5:80"))
	if req := fx.next(t, opened).Opened; req.Op != rules.OpConnect || req.Syscall != "sendto" {
		t.Fatalf("fast open: %+v", req)
	} else if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, id, int32(unix.EACCES))
}

func TestNetUnix(t *testing.T) {
	fx := setup(t, nil, false)
	f := fx.f
	// A bound socket, reached through a symlink.
	path := filepath.Join(fx.dir, "s.sock")
	srv := sock(t, unix.AF_UNIX, unix.SOCK_DGRAM)
	if err := unix.Bind(srv, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Symlink(path, fx.dir+"/link"); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.m.Apply(rulesDecision(
		netRule(t, "unix:"+path, rules.Allow),
		netRule(t, "unix:@deny*", rules.Deny),
	)); err != nil {
		t.Fatal(err)
	}
	dgram, stream := sock(t, unix.AF_UNIX, unix.SOCK_DGRAM), sock(t, unix.AF_UNIX, unix.SOCK_STREAM)
	f.expect(t, f.sendto(dgram, 0, sockaddrUnix(fx.dir+"/link")), 0)
	f.expect(t, f.connect(stream, sockaddrUnix("@deny-me")), int32(unix.EACCES))
	// Stream sockets ignore the address of a send.
	f.expect(t, f.sendto(stream, 0, sockaddrUnix("@deny-me")), 0)
	// No such socket: the kernel fails it.
	f.expect(t, f.connect(stream, sockaddrUnix(fx.dir+"/none")), 0)
	// An inet address on a unix socket: the kernel fails it.
	f.expect(t, f.connect(stream, sockaddrInet("198.51.100.1:80")), 0)

	id := f.sendmsg(dgram, sockaddrUnix("@other"))
	req := fx.next(t, opened).Opened
	if o := req.Objects[0].Unix; req.Op != rules.OpSend || o == nil || !o.Abstract || o.Name != "other" || o.Type != unix.SOCK_DGRAM {
		t.Fatalf("request %+v %+v", req, req.Objects[0])
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, id, 0)
}

func rulesDecision(rs ...rules.Rule) Decision { return Decision{AddRules: rs} }

// TestNetOwnListener: listeners held by the workload (here, the test
// process) get the OwnListener fact, which an implicit rule allows.
func TestNetOwnListener(t *testing.T) {
	if err := netdiag.Supported(); errors.Is(err, unix.ENOENT) {
		t.Skipf("kernel without sock_diag: %v", err)
	}
	fx := setup(t, nil, false)
	f := fx.f
	ln := sock(t, unix.AF_INET, unix.SOCK_STREAM)
	if err := unix.Bind(ln, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(ln, 1); err != nil {
		t.Fatal(err)
	}
	sa, err := unix.Getsockname(ln)
	if err != nil {
		t.Fatal(err)
	}
	port := sa.(*unix.SockaddrInet4).Port
	path := filepath.Join(fx.dir, "own.sock")
	uln := sock(t, unix.AF_UNIX, unix.SOCK_STREAM)
	if err := unix.Bind(uln, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	if err := unix.Listen(uln, 1); err != nil {
		t.Fatal(err)
	}
	tcp, tcp6 := sock(t, unix.AF_INET, unix.SOCK_STREAM), sock(t, unix.AF_INET6, unix.SOCK_STREAM)
	stream := sock(t, unix.AF_UNIX, unix.SOCK_STREAM)

	// Without the rule: asked, with the fact.
	id := f.connect(tcp6, sockaddrInet(fmt.Sprintf("[::ffff:127.0.0.1]:%d", port)))
	req := fx.next(t, opened).Opened
	if o := req.Objects[0].Inet; o == nil || !o.OwnListener {
		t.Fatalf("request %+v %+v", req, req.Objects[0])
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, id, int32(unix.EACCES))

	if _, err := fx.m.Apply(rulesDecision(
		rules.Rule{Ops: rules.OpNet, Verdict: rules.Allow, Object: rules.ObjectMatch{OwnListener: true}},
		netRule(t, "tcp:127.0.0.1:1", rules.Deny),
	)); err != nil {
		t.Fatal(err)
	}
	f.expect(t, f.connect(tcp, sockaddrInet(fmt.Sprintf("127.0.0.1:%d", port))), 0)
	f.expect(t, f.connect(stream, sockaddrUnix(path)), 0)
	// No listener there.
	f.expect(t, f.connect(tcp, sockaddrInet("127.0.0.1:1")), int32(unix.EACCES))
	id = f.connect(tcp, sockaddrInet(fmt.Sprintf("127.0.0.2:%d", port)))
	if req := fx.next(t, opened).Opened; req.Objects[0].Inet.OwnListener {
		t.Errorf("127.0.0.2: own listener")
	} else if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, id, int32(unix.EACCES))
}
