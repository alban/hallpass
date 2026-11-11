// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsnames

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// response builds a DNS response to qs with answers rrs.
func response(t *testing.T, rcode dnsmessage.RCode, qs []dnsmessage.Question, rrs ...dnsmessage.Resource) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: true, RCode: rcode})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, r := range rrs {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(r.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(r.Header, *body)
		case *dnsmessage.CNAMEResource:
			err = b.CNAMEResource(r.Header, *body)
		case *dnsmessage.TXTResource:
			err = b.TXTResource(r.Header, *body)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func rr(name string, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: ttl}, Body: body}
}

func a4(s string) *dnsmessage.AResource {
	return &dnsmessage.AResource{A: netip.MustParseAddr(s).As4()}
}

func cname(s string) *dnsmessage.CNAMEResource {
	return &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(s)}
}

func TestAnswers(t *testing.T) {
	objs := []dnsmessage.Question{q("Objects.GitHubUserContent.com.", dnsmessage.TypeA)}
	chain := response(t, dnsmessage.RCodeSuccess, objs,
		rr("objects.githubusercontent.com.", 3600, cname("github.map.fastly.net.")),
		rr("github.map.fastly.net.", 30, a4("185.199.108.133")),
		rr("github.map.fastly.net.", 60, a4("185.199.109.133")),
		// Not on the chain: ignored.
		rr("evil.example.", 60, a4("6.6.6.6")),
		rr("objects.githubusercontent.com.", 60, &dnsmessage.TXTResource{TXT: []string{"x"}}),
	)
	got := Answers(chain)
	want := Answered{
		Names: []string{"objects.githubusercontent.com", "github.map.fastly.net"},
		Addrs: []netip.Addr{netip.MustParseAddr("185.199.108.133"), netip.MustParseAddr("185.199.109.133")},
		TTL:   30 * time.Second,
	}
	if len(got) != 1 || !slices.Equal(got[0].Names, want.Names) || !slices.Equal(got[0].Addrs, want.Addrs) || got[0].TTL != want.TTL {
		t.Errorf("chain: %+v, want %+v", got, want)
	}
	aaaa := response(t, dnsmessage.RCodeSuccess, []dnsmessage.Question{q("v6.example.", dnsmessage.TypeAAAA)},
		rr("v6.example.", 300, &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::1").As16()}))
	if got := Answers(aaaa); len(got) != 1 || got[0].Addrs[0] != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("AAAA: %+v", got)
	}
	// A CNAME loop ends.
	loop := response(t, dnsmessage.RCodeSuccess, []dnsmessage.Question{q("a.example.", dnsmessage.TypeA)},
		rr("a.example.", 60, cname("b.example.")), rr("b.example.", 60, cname("a.example.")))
	if got := Answers(loop); got != nil {
		t.Errorf("loop: %+v", got)
	}
	for name, msg := range map[string][]byte{
		"nxdomain": response(t, dnsmessage.RCodeNameError, objs, rr("objects.githubusercontent.com.", 60, a4("1.2.3.4"))),
		"query":    query(t, false, objs...),
		"mx":       response(t, dnsmessage.RCodeSuccess, []dnsmessage.Question{q("a.example.", dnsmessage.TypeMX)}, rr("a.example.", 60, a4("1.2.3.4"))),
		"garbage":  []byte("HTTP/1.1 200 OK\r\n"),
		"cut":      chain[:len(chain)-5],
	} {
		if got := Answers(msg); got != nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
}

func TestAnswerMsg(t *testing.T) {
	n := New()
	now := time.Unix(1000, 0)
	n.now = func() time.Time { return now }
	n.AnswerMsg(response(t, dnsmessage.RCodeSuccess, []dnsmessage.Question{q("objects.githubusercontent.com.", dnsmessage.TypeA)},
		rr("objects.githubusercontent.com.", 3600, cname("github.map.fastly.net.")),
		rr("github.map.fastly.net.", 7200, a4("185.199.108.133"))))
	addr := netip.MustParseAddr("185.199.108.133")
	if got := n.Lookup(addr); !slices.Equal(got, []string{"objects.githubusercontent.com", "github.map.fastly.net"}) {
		t.Errorf("names: %q", got)
	}
	// The TTL when longer than Floor.
	now = now.Add(time.Hour - time.Second)
	if got := n.Lookup(addr); len(got) != 2 {
		t.Errorf("before the TTL: %q", got)
	}
	now = now.Add(time.Second)
	if got := n.Lookup(addr); got != nil {
		t.Errorf("after the TTL: %q", got)
	}
	// Names that are no host names are not kept.
	n.Answer("evil\x1b[2J.example", []netip.Addr{addr}, 0)
	if got := n.Lookup(addr); got != nil {
		t.Errorf("escape kept: %q", got)
	}
}

func TestVarlink(t *testing.T) {
	n := New()
	v := NewVarlink(n)
	gh, gh6 := netip.MustParseAddr("140.82.112.4"), netip.MustParseAddr("2001:db8::4")
	// Pipelined: a oneway call has no reply, a "more" call several.
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"GitHub.com.","family":0}}`))
	v.Call([]byte(`{"method":"io.systemd.Resolve.Monitor.SubscribeQueryResults","oneway":true}`))
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveAddress","parameters":{"family":2,"address":[1,2,3,4]}}`))
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"more.example"},"more":true}`))
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"nx.example"}}`))
	v.Reply([]byte(`{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[140,82,112,4]},{"family":10,"address":[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,4]}],"name":"github.com","flags":1}}`))
	// The reply to ResolveAddress: its names are not on 1.2.3.4.
	v.Reply([]byte(`{"parameters":{"names":[{"name":"github.com"}]}}`))
	v.Reply([]byte(`{"parameters":{"addresses":[{"family":2,"address":[10,0,0,1]}]},"continues":true}`))
	v.Reply([]byte(`{"parameters":{"addresses":[{"family":2,"address":[10,0,0,2]}]}}`))
	v.Reply([]byte(`{"error":"io.systemd.Resolve.NoSuchResourceRecord","parameters":{"addresses":[{"family":2,"address":[10,0,0,3]}]}}`))
	for addr, want := range map[netip.Addr][]string{
		gh:                                {"github.com"},
		gh6:                               {"github.com"},
		netip.MustParseAddr("1.2.3.4"):    nil,
		netip.MustParseAddr("10.0.0.1"):   {"more.example"},
		netip.MustParseAddr("10.0.0.2"):   {"more.example"},
		netip.MustParseAddr("10.0.0.3"):   nil,
		netip.MustParseAddr("140.82.0.0"): nil,
	} {
		if got := n.Lookup(addr); !slices.Equal(got, want) {
			t.Errorf("%v: %q, want %q", addr, got, want)
		}
	}
	if v.Done() {
		t.Error("stopped following")
	}
	// A reply without a call, bad JSON, addresses out of range, an
	// upgrade: no longer followed.
	for _, c := range []struct{ call, reply string }{
		{"", `{"parameters":{}}`},
		{`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"x.example"}}`, `{"parameters":`},
		{`{"method":"x","upgrade":true}`, ""},
	} {
		v := NewVarlink(n)
		if c.call != "" {
			v.Call([]byte(c.call))
		}
		if c.reply != "" {
			v.Reply([]byte(c.reply))
		}
		if !v.Done() {
			t.Errorf("%q %q: still followed", c.call, c.reply)
		}
	}
	v = NewVarlink(n)
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"range.example"}}`))
	v.Reply([]byte(`{"parameters":{"addresses":[{"family":2,"address":[256,0,0,1]},{"family":2,"address":[1,0,0]}]}}`))
	if got := n.Lookup(netip.MustParseAddr("0.0.0.1")); got != nil {
		t.Errorf("out of range: %q", got)
	}
}

func TestUnverified(t *testing.T) {
	addr := netip.MustParseAddr("140.82.112.4")
	calls := 0
	n := New()
	n.SetReverse(func(ctx context.Context, a netip.Addr) ([]string, error) {
		calls++
		if a != addr {
			return nil, errors.New("no such host")
		}
		return []string{"lb-140-82-112-4-iad.GitHub.com.", "bad\x1bname."}, nil
	})
	// Not before the session's own DNS was allowed.
	if got := n.Unverified(addr, time.Second); got != nil || calls != 0 {
		t.Fatalf("before DNS: %q, %d lookups", got, calls)
	}
	n.Answer("other.example", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, 0)
	if got := n.Unverified(addr, time.Second); !slices.Equal(got, []string{"lb-140-82-112-4-iad.github.com"}) {
		t.Errorf("PTR: %q", got)
	}
	n.Unverified(addr, time.Second)
	if calls != 1 {
		t.Errorf("%d lookups, want 1 (remembered)", calls)
	}
	if got := n.Unverified(netip.MustParseAddr("127.0.0.1"), time.Second); got != nil || calls != 1 {
		t.Errorf("loopback looked up: %q", got)
	}
	// PTR names never name an address for rules.
	if got := n.Lookup(addr); got != nil {
		t.Errorf("Lookup gives PTR names: %q", got)
	}
}

func TestDisplayOnly(t *testing.T) {
	n := New()
	a := netip.MustParseAddr("192.0.2.1")
	n.Answer("api.example", []netip.Addr{a}, 0)
	if got := n.Match(a); len(got) != 1 {
		t.Errorf("Match %q", got)
	}
	n.SetDisplayOnly()
	if got := n.Match(a); got != nil {
		t.Errorf("display only, Match %q", got)
	}
	if got := n.Lookup(a); len(got) != 1 {
		t.Errorf("display only, Lookup %q", got)
	}
}

// TestVarlinkDuplicateKeys: a call with a key twice, or in another case,
// stops the follower: resolved may read it otherwise.
func TestVarlinkDuplicateKeys(t *testing.T) {
	for _, call := range []string{
		`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"a.example"},"oneway":true,"oneway":false}`,
		`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"a.example","Name":"b.example"}}`,
		`{"method":"io.systemd.Resolve.ResolveHostname","Oneway":true,"parameters":{"name":"a.example"},"oneway":false}`,
		`{"method":"x"} {"method":"y"}`,
	} {
		v := NewVarlink(New())
		v.Call([]byte(call))
		if !v.Done() {
			t.Errorf("%s: still followed", call)
		}
	}
	v := NewVarlink(New())
	v.Call([]byte(`{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"a.example","family":0}}`))
	if v.Done() {
		t.Error("a plain call stopped the follower")
	}
}
