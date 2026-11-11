// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsnames

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
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

func TestNames(t *testing.T) {
	gh, cdn := netip.MustParseAddr("140.82.112.4"), netip.MustParseAddr("104.16.0.1")
	n := New()
	now := time.Unix(1000, 0)
	n.now = func() time.Time { return now }

	n.Answer("GitHub.com.", []netip.Addr{gh}, time.Minute)
	if got := n.Lookup(gh); !slices.Equal(got, []string{"github.com"}) {
		t.Errorf("github.com: %q", got)
	}
	// Two names on one address: the most recent first; an IPv4-mapped
	// address is the IPv4 one.
	n.Answer("a.example", []netip.Addr{cdn}, 0)
	n.Answer("b.example", []netip.Addr{cdn, netip.MustParseAddr("::ffff:104.16.0.2")}, 0)
	if got := n.Lookup(cdn); !slices.Equal(got, []string{"b.example", "a.example"}) {
		t.Errorf("shared address: %q", got)
	}
	if got := n.Lookup(netip.MustParseAddr("104.16.0.2")); !slices.Equal(got, []string{"b.example"}) {
		t.Errorf("mapped: %q", got)
	}
	if got := n.Lookup(netip.MustParseAddr("192.0.2.1")); got != nil {
		t.Errorf("unknown: %q", got)
	}
	// Names expire after Floor, at least.
	now = now.Add(Floor)
	if got := n.Lookup(gh); got != nil {
		t.Errorf("expired: %q", got)
	}
}

func TestServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	conf := "# nameserver 192.0.2.9\nnameserver 127.0.0.53\nsearch .\nnameserver ::ffff:10.0.0.1\nnameserver fe80::1%eth0\nnameserver bogus\noptions edns0\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	servers, err := Servers(path)
	want := []netip.Addr{netip.MustParseAddr("127.0.0.53"), netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("fe80::1")}
	if err != nil || !slices.Equal(servers, want) {
		t.Fatalf("Servers: %v %v, want %v", servers, err, want)
	}
}

// TestHostReverseServers: without servers, a reverse lookup reaches no
// server.
func TestHostReverseServers(t *testing.T) {
	if names, err := HostReverse(nil)(t.Context(), netip.MustParseAddr("192.0.2.1")); err == nil {
		t.Errorf("looked up without servers: %q", names)
	}
}
