// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsnames

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, response bool, qs ...dnsmessage.Question) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, Response: response, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func q(name string, typ dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}
}

func TestQueryNames(t *testing.T) {
	for _, c := range []struct {
		msg  []byte
		want []string
	}{
		{query(t, false, q("GitHub.com.", dnsmessage.TypeA)), []string{"github.com"}},
		{query(t, false, q("a.example.", dnsmessage.TypeA), q("a.example.", dnsmessage.TypeAAAA), q("b.example.", dnsmessage.TypeAAAA)), []string{"a.example", "b.example"}},
		{query(t, false, q("mail.example.", dnsmessage.TypeMX)), nil},
		{query(t, true, q("github.com.", dnsmessage.TypeA)), nil},
		{[]byte("GET / HTTP/1.1\r\n"), nil},
		{nil, nil},
	} {
		if got := QueryNames(c.msg); !slices.Equal(got, c.want) {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

// fakeDNS answers lookups from a table, counting them; a name in block
// waits for release.
type fakeDNS struct {
	mu      sync.Mutex
	table   map[string][]netip.Addr
	calls   atomic.Int32
	block   string
	release chan struct{}
}

func (f *fakeDNS) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	f.calls.Add(1)
	if name == f.block {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.table[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func TestNames(t *testing.T) {
	gh, cdn := netip.MustParseAddr("140.82.112.4"), netip.MustParseAddr("104.16.0.1")
	f := &fakeDNS{table: map[string][]netip.Addr{
		"github.com":   {gh},
		"a.example":    {cdn},
		"b.example":    {cdn, netip.MustParseAddr("::ffff:104.16.0.2")},
		"slow.example": {netip.MustParseAddr("10.0.0.1")},
	}, block: "slow.example", release: make(chan struct{})}
	n := New(f.lookup)
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	n.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	n.Observe("github.com")
	if got := n.Lookup(gh, time.Second); !slices.Equal(got, []string{"github.com"}) {
		t.Errorf("github.com: %q", got)
	}
	// Two names on one address: the most recent first; an IPv4-mapped
	// address is the IPv4 one.
	n.Observe("a.example")
	n.Lookup(cdn, time.Second)
	n.Observe("b.example")
	if got := n.Lookup(cdn, time.Second); !slices.Equal(got, []string{"b.example", "a.example"}) {
		t.Errorf("shared address: %q", got)
	}
	if got := n.Lookup(netip.MustParseAddr("104.16.0.2"), 0); !slices.Equal(got, []string{"b.example"}) {
		t.Errorf("mapped: %q", got)
	}
	// An unknown name, an unknown address.
	n.Observe("nope.example")
	if got := n.Lookup(netip.MustParseAddr("192.0.2.1"), time.Second); got != nil {
		t.Errorf("unknown: %q", got)
	}
	// A recent lookup is not repeated.
	calls := f.calls.Load()
	n.Observe("github.com")
	n.Lookup(gh, time.Second)
	if f.calls.Load() != calls {
		t.Error("looked up again at once")
	}
	// Lookup waits for a lookup in progress, at most wait.
	n.Observe("slow.example")
	if got := n.Lookup(netip.MustParseAddr("10.0.0.1"), 10*time.Millisecond); got != nil {
		t.Errorf("did not wait at most wait: %q", got)
	}
	close(f.release)
	if got := n.Lookup(netip.MustParseAddr("10.0.0.1"), time.Second); !slices.Equal(got, []string{"slow.example"}) {
		t.Errorf("slow: %q", got)
	}
	// Names expire after Floor.
	advance(Floor)
	if got := n.Lookup(gh, 0); got != nil {
		t.Errorf("expired: %q", got)
	}
}
