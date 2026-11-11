// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/rules"
)

// TestProbe: a UDP connect that looks like a resolver's sorting probe is
// done without asking, and nothing can be sent on the socket, even
// after another connect; other connects are asked about, or decided by
// the rules.
func TestProbe(t *testing.T) {
	names := dnsnames.New()
	names.Answer("a.example", []netip.Addr{netip.MustParseAddr("127.0.0.3")}, 0)
	fx := setupConfig(t, Config{Names: names, DNSForward: map[netip.Addr]netip.AddrPort{
		netip.MustParseAddr("127.0.0.3"): netip.MustParseAddrPort("127.0.0.1:1"),
	}}, true)
	if _, err := fx.m.Apply(rulesDecision(netRule(t, "udp:127.0.0.5", rules.Deny))); err != nil {
		t.Fatal(err)
	}
	names.Answer("b.example", []netip.Addr{netip.MustParseAddr("127.0.0.4")}, 0)
	f := fx.f
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	sinkSA := &unix.SockaddrInet4{Port: sink.LocalAddr().(*net.UDPAddr).Port, Addr: [4]byte{127, 0, 0, 1}}

	for _, c := range []struct {
		domain int
		dst    string
	}{
		{unix.AF_INET, "127.0.0.2:0"},               // glibc
		{unix.AF_INET, "127.0.0.2:65535"},           // musl
		{unix.AF_INET, "127.0.0.4:53"},              // Go, to an answer's address
		{unix.AF_INET6, "[::ffff:127.0.0.2]:65535"}, // musl, IPv6 socket
	} {
		fd := sock(t, c.domain, unix.SOCK_DGRAM)
		f.expectVal(t, f.connect(fd, sockaddrInet(c.dst)), 0)
		if d := fx.next(t, func(ev Event) bool { return ev.Decided != nil }).Decided; !d.Allowed || d.Why[0].Builtin != "probe" {
			t.Errorf("%s: decided %+v", c.dst, d)
		}
		if sa, err := unix.Getsockname(fd); err != nil {
			t.Errorf("%s: getsockname %v", c.dst, err)
		} else if a, ok := sa.(*unix.SockaddrInet4); ok && a.Addr == [4]byte{} {
			t.Errorf("%s: no source address", c.dst)
		}
		if err := unix.Send(fd, []byte("x"), unix.MSG_NOSIGNAL); err != unix.EPIPE {
			t.Errorf("%s: send %v, want EPIPE", c.dst, err)
		}
		if c.domain == unix.AF_INET {
			if err := unix.Sendto(fd, []byte("x"), unix.MSG_NOSIGNAL, sinkSA); err != unix.EPIPE {
				t.Errorf("%s: sendto %v, want EPIPE", c.dst, err)
			}
			if err := unix.Connect(fd, sinkSA); err != nil {
				t.Fatal(err)
			}
			if err := unix.Send(fd, []byte("x"), unix.MSG_NOSIGNAL); err != unix.EPIPE {
				t.Errorf("%s: send after connect %v, want EPIPE", c.dst, err)
			}
		}
	}
	_ = sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if n, _, err := sink.ReadFrom(make([]byte, 8)); err == nil {
		t.Errorf("sink received %d bytes", n)
	}

	// Asked: TCP; another port; port 53 of a name server, or of an
	// address of no answer.
	for _, c := range []struct {
		typ int
		dst string
	}{
		{unix.SOCK_STREAM, "127.0.0.2:65535"},
		{unix.SOCK_DGRAM, "127.0.0.2:9"},
		{unix.SOCK_DGRAM, "127.0.0.3:53"},
		{unix.SOCK_DGRAM, "127.0.0.2:53"},
	} {
		id := f.connect(sock(t, unix.AF_INET, c.typ), sockaddrInet(c.dst))
		req := fx.next(t, opened).Opened
		if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
			t.Fatal(err)
		}
		f.expect(t, id, int32(unix.EACCES))
	}
	// A rule decides first.
	f.expect(t, f.connect(sock(t, unix.AF_INET, unix.SOCK_DGRAM), sockaddrInet("127.0.0.5:0")), int32(unix.EACCES))
}
