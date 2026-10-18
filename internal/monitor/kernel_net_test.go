// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"golang.org/x/sys/unix"
)

func TestToLSMNet(t *testing.T) {
	for _, tc := range []struct {
		spec   string
		v      rules.Verdict
		ops    rules.Op
		path   *lsm.Rule
		net    lsm.NetRules
		unsupp bool
	}{
		{spec: "all", v: rules.Allow, net: lsm.NetRules{Inet: []lsm.InetRule{{}}, AnyUnix: []lsm.UnixAnyRule{{}}}},
		{spec: "tcp:10.0.0.0/8:443", v: rules.Deny, net: lsm.NetRules{Inet: []lsm.InetRule{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Proto: unix.IPPROTO_TCP, PortLo: 443, PortHi: 443, Deny: true}}}},
		{spec: "unix:@x*", v: rules.Allow, net: lsm.NetRules{Abstract: []lsm.AbstractRule{{Name: "x", Prefix: true}}}},
		{spec: "unix:/run/**", v: rules.Allow, path: &lsm.Rule{Path: "/run", Tree: true, Net: true}},
		{spec: "1.2.3.4", v: rules.Ask, unsupp: true},
		{spec: "1.2.3.4", v: rules.Allow, ops: rules.OpConnect, unsupp: true},
	} {
		r := netRule(t, tc.spec, tc.v)
		if tc.ops != 0 {
			r.Ops = tc.ops
		}
		var net lsm.NetRules
		p, _, err := toLSM(r, &net)
		if tc.unsupp {
			if !errors.Is(err, ErrUnsupported) {
				t.Errorf("%s: %v, want unsupported", tc.spec, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.spec, err)
			continue
		}
		if (p == nil) != (tc.path == nil) || p != nil && *p != *tc.path {
			t.Errorf("%s: path rule %+v, want %+v", tc.spec, p, tc.path)
		}
		if !equalNet(net, tc.net) {
			t.Errorf("%s: %+v, want %+v", tc.spec, net, tc.net)
		}
	}
	var net lsm.NetRules
	if _, _, err := toLSM(rules.Rule{Ops: rules.OpNet, Verdict: rules.Allow, Object: rules.ObjectMatch{OwnListener: true}}, &net); err != nil || !net.OwnListeners {
		t.Errorf("own listeners: %v %+v", err, net)
	}
	if _, _, err := toLSM(rules.Rule{Ops: rules.OpNet, Verdict: rules.Deny, Object: rules.ObjectMatch{OwnListener: true}}, &net); !errors.Is(err, ErrUnsupported) {
		t.Errorf("deny own listeners: %v", err)
	}
}

func equalNet(a, b lsm.NetRules) bool {
	if len(a.Inet) != len(b.Inet) || len(a.Abstract) != len(b.Abstract) || len(a.AnyUnix) != len(b.AnyUnix) || a.OwnListeners != b.OwnListeners {
		return false
	}
	for i := range a.Inet {
		if a.Inet[i] != b.Inet[i] {
			return false
		}
	}
	for i := range a.Abstract {
		if a.Abstract[i] != b.Abstract[i] {
			return false
		}
	}
	for i := range a.AnyUnix {
		if a.AnyUnix[i] != b.AnyUnix[i] {
			return false
		}
	}
	return true
}

// TestNetStrict: rules go to the kernel, and a "once" answer becomes a
// grant of the address to the thread.
func TestNetStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	if _, err := fx.m.Apply(rulesDecision(netRule(t, "tcp:192.0.2.0/24:443", rules.Allow))); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	if len(k.net.Inet) != 1 || k.net.Inet[0].Prefix != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("kernel rules %+v", k.net)
	}
	k.mu.Unlock()
	if _, err := fx.m.Apply(rulesDecision(netRule(t, "10.0.0.1", rules.Ask))); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ask rule: %v", err)
	}

	tcp := sock(t, unix.AF_INET, unix.SOCK_STREAM)
	id := fx.f.connect(tcp, sockaddrInet("203.0.113.5:22"))
	req := fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	k.mu.Lock()
	defer k.mu.Unlock()
	want := lsm.InetDest{Addr: netip.MustParseAddrPort("203.0.113.5:22"), Proto: unix.IPPROTO_TCP}
	if n := len(k.netGrants); n == 0 || len(k.netGrants[n-1].Inet) != 1 || k.netGrants[n-1].Inet[0] != want {
		t.Fatalf("grants %+v", k.netGrants)
	}
}
