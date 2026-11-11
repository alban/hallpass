// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
)

// testServer is the name server whose queries the redirect tests send to
// their forwarder: never reached.
const testServer = "192.0.2.53:53"

// redirectFixture is a monitor redirecting the queries to testServer to
// fwd, a UDP socket standing for the forwarder.
func redirectFixture(t *testing.T) (*fixture, *net.UDPConn) {
	t.Helper()
	netns, err := procfs.Netns()
	if err != nil || netns == 0 {
		t.Skip("no network namespace cookie")
	}
	fwd, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fwd.Close() })
	server := netip.MustParseAddrPort(testServer)
	fx := setupConfig(t, Config{Netns: netns, DNSForward: map[netip.Addr]netip.AddrPort{server.Addr(): fwd.LocalAddr().(*net.UDPAddr).AddrPort()}}, false)
	if _, err := fx.m.Apply(rulesDecision(netRule(t, "udp:"+testServer, rules.Allow))); err != nil {
		t.Fatal(err)
	}
	return fx, fwd
}

func (f *fakeNotifier) expectVal(t *testing.T, id uint64, val int64) {
	t.Helper()
	select {
	case r := <-f.out:
		if r.id != id || r.errno != 0 || r.val != val {
			t.Fatalf("response %+v, want {id:%d val:%d}", r, id, val)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no response for %d", id)
	}
}

// sendtoData notifies sendto(fd, b, len(b), 0, sa).
func (f *fakeNotifier) sendtoData(fd int, b, sa []byte) uint64 {
	return f.send(unix.SYS_SENDTO, nil, map[int]uint64{0: uint64(fd), 1: f.keep(b), 2: uint64(len(b)), 3: 0, 4: f.keep(sa), 5: uint64(len(sa))})
}

// recvfrom notifies recvfrom(fd, buf, len(buf), flags, from, &fromLen).
func (f *fakeNotifier) recvfrom(fd int, buf, from []byte, flags int, fromLen *uint32) uint64 {
	*fromLen = uint32(len(from))
	f.mu.Lock()
	f.alive = append(f.alive, fromLen)
	f.mu.Unlock()
	return f.send(unix.SYS_RECVFROM, nil, map[int]uint64{0: uint64(fd), 1: f.keep(buf), 2: uint64(len(buf)), 3: uint64(flags), 4: f.keep(from), 5: uint64(uintptr(unsafe.Pointer(fromLen)))})
}

// recvmsg notifies recvmsg(fd, h, 0), h receiving in buf with source from.
func (f *fakeNotifier) recvmsg(fd int, buf, from []byte, h *unix.Msghdr) uint64 {
	iov := &unix.Iovec{Base: &buf[0]}
	iov.SetLen(len(buf))
	f.keep(buf)
	f.keep(from)
	h.Name, h.Namelen = &from[0], uint32(len(from))
	h.Iov = iov
	h.SetIovlen(1)
	f.mu.Lock()
	f.alive = append(f.alive, h, iov)
	f.mu.Unlock()
	return f.send(unix.SYS_RECVMSG, nil, map[int]uint64{0: uint64(fd), 1: uint64(uintptr(unsafe.Pointer(h))), 2: 0})
}

// query reads a datagram at the forwarder, and answers it with reply.
func query(t *testing.T, fwd *net.UDPConn, want, reply string) {
	t.Helper()
	_ = fwd.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 512)
	n, from, err := fwd.ReadFromUDPAddrPort(b)
	if err != nil {
		t.Fatalf("forwarder: %v", err)
	}
	if string(b[:n]) != want {
		t.Fatalf("forwarder got %q, want %q", b[:n], want)
	}
	if _, err := fwd.WriteToUDPAddrPort([]byte(reply), from); err != nil {
		t.Fatal(err)
	}
}

// TestDNSRedirect: an allowed connect or sendto to a name server goes to
// the forwarder, and the replies' source, asked by recvfrom or recvmsg,
// is the server.
func TestDNSRedirect(t *testing.T) {
	fx, fwd := redirectFixture(t)
	f := fx.f
	server := sockaddrInet(testServer)

	// glibc, Go: connect, then send without an address.
	udp := sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	f.expectVal(t, f.connect(udp, server), 0)
	if _, err := unix.Write(udp, []byte("q1")); err != nil {
		t.Fatal(err)
	}
	query(t, fwd, "q1", "a1")
	buf, from := make([]byte, 64), make([]byte, unix.SizeofSockaddrInet4)
	var fromLen uint32
	f.expectVal(t, f.recvfrom(udp, buf, from, 0, &fromLen), 2)
	if string(buf[:2]) != "a1" || fromLen != unix.SizeofSockaddrInet4 || !bytes.Equal(from, server) {
		t.Errorf("recvfrom %q from %x (%d), want a1 from %x", buf[:2], from, fromLen, server)
	}

	// musl: sendto with an address, recvmsg with msg_name.
	udp2 := sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	f.expectVal(t, f.sendtoData(udp2, []byte("q2"), server), 2)
	query(t, fwd, "q2", "a2")
	var h unix.Msghdr
	from = make([]byte, unix.SizeofSockaddrInet6)
	f.expectVal(t, f.recvmsg(udp2, buf, from, &h), 2)
	if string(buf[:2]) != "a2" || h.Namelen != unix.SizeofSockaddrInet4 || !bytes.Equal(from[:h.Namelen], server) {
		t.Errorf("recvmsg %q from %x (%d), want a2 from %x", buf[:2], from[:h.Namelen], h.Namelen, server)
	}

	// A blocking receive waits for the reply.
	id := f.recvfrom(udp, buf, from, 0, &fromLen)
	f.expectNone(t)
	if _, err := unix.Write(udp, []byte("q3")); err != nil {
		t.Fatal(err)
	}
	query(t, fwd, "q3", "a3")
	f.expectVal(t, id, 2)

	// Non-blocking, nothing to receive.
	f.expect(t, f.recvfrom(udp, buf, from, unix.MSG_DONTWAIT, &fromLen), int32(unix.EAGAIN))

	// Not redirected: continued.
	other := sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	f.expect(t, f.recvfrom(other, buf, from, 0, &fromLen), 0)
}

// TestDNSRedirectDup: the redirect is of the socket, not of the
// descriptor: sent through a copy of the descriptor connected to the
// server, a query reaches the forwarder.
func TestDNSRedirectDup(t *testing.T) {
	fx, fwd := redirectFixture(t)
	f := fx.f
	fd := sock(t, unix.AF_INET, unix.SOCK_DGRAM)
	fd2, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd2)
	f.expectVal(t, f.connect(fd2, sockaddrInet(testServer)), 0)
	if _, err := unix.Write(fd, []byte("q")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Send(fd, []byte("q"), 0); err != nil {
		t.Fatal(err)
	}
	query(t, fwd, "q", "a")
	query(t, fwd, "q", "")
	buf, from := make([]byte, 64), make([]byte, unix.SizeofSockaddrInet4)
	var fromLen uint32
	f.expectVal(t, f.recvfrom(fd, buf, from, 0, &fromLen), 1)
	if !bytes.Equal(from, sockaddrInet(testServer)) {
		t.Errorf("source %x", from)
	}
}

// TestDNSRedirectSet: a socket is forgotten once its inode is another
// socket's, and the oldest past maxRedirected.
func TestDNSRedirectSet(t *testing.T) {
	var s redirectSet
	s.add(1, 10)
	if !s.is(1, 10) || s.is(1, 11) || s.has(1) {
		t.Fatal("inode 1 of cookie 10: not forgotten for cookie 11")
	}
	for i := range uint64(maxRedirected + 1) {
		s.add(100+i, i)
	}
	if s.has(100) || !s.has(101) || len(s.cookie) != maxRedirected {
		t.Errorf("%d remembered", len(s.cookie))
	}
}
