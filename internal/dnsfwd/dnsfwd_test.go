// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsfwd

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeServer answers A queries on UDP and TCP from table: name -> address.
// A name ending in "big." gets a truncated UDP reply (TC), and its answer
// over TCP.
func fakeServer(t *testing.T, table map[string]string) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	ap := netip.MustParseAddrPort(pc.LocalAddr().String())
	tl, err := net.Listen("tcp4", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tl.Close() })
	answer := func(q []byte, tcp bool) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if f, ok := table["forge"]; ok && err == nil {
			// Answer with another ID: not a reply to the query.
			h.ID++
			delete(table, "forge")
			defer func() { table["forge"] = f }()
		}
		if err != nil {
			return nil
		}
		qs, err := p.AllQuestions()
		if err != nil || len(qs) != 1 {
			return nil
		}
		name := qs[0].Name.String()
		trunc := !tcp && len(name) > 4 && name[len(name)-4:] == "big."
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Truncated: trunc})
		b.StartQuestions()
		b.Question(qs[0])
		b.StartAnswers()
		if a, ok := table[name]; ok && !trunc {
			b.AResource(dnsmessage.ResourceHeader{Name: qs[0].Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: netip.MustParseAddr(a).As4()})
		}
		msg, _ := b.Finish()
		return msg
	}
	go func() {
		b := make([]byte, 512)
		for {
			k, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(answer(b[:k], false), from)
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					var hdr [2]byte
					if _, err := io.ReadFull(c, hdr[:]); err != nil {
						return
					}
					q := make([]byte, binary.BigEndian.Uint16(hdr[:]))
					if _, err := io.ReadFull(c, q); err != nil {
						return
					}
					r := answer(q, true)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}()
		}
	}()
	return ap
}

func query(t *testing.T, id uint16, name string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func direct(f func() error) error { return f() }

func start(t *testing.T, table map[string]string) (*Forwarder, *dnsnames.Names, netip.AddrPort) {
	t.Helper()
	srv := fakeServer(t, table)
	names := dnsnames.New()
	f, err := Start(direct, []netip.AddrPort{srv}, names, func(s string) { t.Log(s) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)
	ls := f.Listeners()
	if len(ls) != 1 || ls[0].Server != srv.Addr() || !ls[0].Addr.Addr().IsLoopback() || ls[0].Addr.Port() == 0 {
		t.Fatalf("listeners %v", ls)
	}
	return f, names, ls[0].Addr
}

// TestUDP: queries of two clients at once get their own replies, byte
// for byte, and the answers are recorded before the clients get them;
// a truncated reply is passed on as it is.
func TestUDP(t *testing.T) {
	_, names, l := start(t, map[string]string{"a.example.": "192.0.2.1", "b.example.": "192.0.2.2", "x.big.": "192.0.2.3"})
	var wg sync.WaitGroup
	for i, name := range []string{"a.example.", "b.example."} {
		wg.Go(func() {
			c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(l))
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.Write(query(t, uint16(100+i), name))
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			b := make([]byte, 512)
			k, err := c.Read(b)
			if err != nil {
				t.Error(err)
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(b[:k])
			q, _ := p.Question()
			if err != nil || h.ID != uint16(100+i) || q.Name.String() != name {
				t.Errorf("%s: reply %+v %v %v", name, h, q, err)
			}
			want := netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i)})
			if got := names.Lookup(want); !slices.Equal(got, []string{name[:len(name)-1]}) {
				t.Errorf("%s: names of %v: %q", name, want, got)
			}
		})
	}
	wg.Wait()

	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(l))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(t, 7, "x.big."))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 512)
	k, err := c.Read(b)
	var p dnsmessage.Parser
	if h, perr := p.Start(b[:k]); err != nil || perr != nil || !h.Truncated {
		t.Errorf("truncated reply: %+v %v %v", h, err, perr)
	}
}

// TestTCP: queries over TCP, two on one connection, are relayed and
// their answers recorded.
func TestTCP(t *testing.T) {
	_, names, l := start(t, map[string]string{"x.big.": "192.0.2.3", "c.example.": "192.0.2.4"})
	c, err := net.Dial("tcp4", l.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i, name := range []string{"x.big.", "c.example."} {
		q := query(t, uint16(i), name)
		c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	}
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := range 2 {
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		if _, err := io.ReadFull(c, make([]byte, binary.BigEndian.Uint16(hdr[:]))); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
	}
	for a, want := range map[string]string{"192.0.2.3": "x.big", "192.0.2.4": "c.example"} {
		if got := names.Lookup(netip.MustParseAddr(a)); !slices.Equal(got, []string{want}) {
			t.Errorf("names of %s: %q", a, got)
		}
	}
}

// TestClose: no listener after Close.
func TestClose(t *testing.T) {
	f, _, l := start(t, nil)
	f.Close()
	if c, err := net.DialTimeout("tcp4", l.String(), time.Second); err == nil {
		c.Close()
		t.Error("TCP listener still open")
	}
}

func TestNoServer(t *testing.T) {
	if _, err := Start(direct, []netip.AddrPort{netip.AddrPortFrom(netip.IPv4Unspecified(), 53)}, dnsnames.New(), nil); err == nil {
		t.Error("started without a server")
	}
}

// TestForged: a reply that answers no query sent (another ID) is not
// recorded.
func TestForged(t *testing.T) {
	_, names, l := start(t, map[string]string{"a.example.": "192.0.2.1", "forge": ""})
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(l))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(query(t, 9, "a.example."))
	c.SetReadDeadline(time.Now().Add(time.Second))
	c.Read(make([]byte, 512))
	if got := names.Lookup(netip.MustParseAddr("192.0.2.1")); got != nil {
		t.Errorf("forged reply recorded: %q", got)
	}
}
