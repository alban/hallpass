// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionnet

import (
	"net/netip"
	"testing"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
)

// denied returns the forwarder listeners m denies.
func denied(m *monitor.Monitor) map[netip.AddrPort]bool {
	_, rs, _ := m.Snapshot()
	out := map[netip.AddrPort]bool{}
	for _, r := range rs {
		if r.Label == labelForwarder && r.Verdict == rules.Deny && r.Set == monitor.ProtectedSet {
			out[netip.AddrPortFrom(r.Object.Inet.Prefix.Addr(), r.Object.Inet.PortLo)] = true
		}
	}
	return out
}

// TestGroup: a session is denied its own forwarder and those of its
// network namespace's other sessions, which are denied its own; a
// session of another namespace is not.
func TestGroup(t *testing.T) {
	g := &Group{Client: "test"}
	type sess struct {
		d *DNS
		m *monitor.Monitor
	}
	var ss []sess
	for i := range 3 {
		d, err := StartDNS(func(f func() error) error { return f() }, []netip.Addr{netip.MustParseAddr("192.0.2.1")}, dnsnames.New(nil, nil), func(string) {})
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(d.Close)
		if i == 2 {
			d.netns++ // another network namespace
		}
		m, err := monitor.New(monitor.Config{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { m.Close() })
		if _, err := g.Join(d, m, func(err error) { t.Error(err) }); err != nil {
			t.Fatal(err)
		}
		ss = append(ss, sess{d, m})
	}
	l := func(i int) netip.AddrPort { return ss[i].d.fwd.Listeners()[0].Addr }
	for i, want := range []map[netip.AddrPort]bool{
		{l(0): true, l(1): true},
		{l(0): true, l(1): true},
		{l(2): true},
	} {
		got := denied(ss[i].m)
		if len(got) != len(want) {
			t.Errorf("session %d denied %v, want %v", i, got, want)
		}
		for ap := range want {
			if !got[ap] {
				t.Errorf("session %d: %v not denied", i, ap)
			}
		}
	}
}
