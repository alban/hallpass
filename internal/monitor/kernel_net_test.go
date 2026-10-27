// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"errors"
	"net/netip"
	"reflect"
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
		unix   lsm.UnixRules
		unsupp bool
	}{
		{spec: "all", v: rules.Allow, unix: lsm.UnixRules{AnyUnix: []lsm.UnixAnyRule{{}}}},
		{spec: "tcp:10.0.0.0/8:443", v: rules.Deny},
		{spec: "unix:@x*", v: rules.Allow},
		{spec: "unix:/run/**", v: rules.Allow, path: &lsm.Rule{Path: "/run", Tree: true, Net: true}},
		{spec: "all", v: rules.Ask, unix: lsm.UnixRules{AnyUnix: []lsm.UnixAnyRule{{Ask: true}}}},
		{spec: "unix:/run/x", v: rules.Ask, path: &lsm.Rule{Path: "/run/x", Ask: true, Net: true}},
		{spec: "1.2.3.4", v: rules.Allow, ops: rules.OpConnect, unsupp: true},
	} {
		r := netRule(t, tc.spec, tc.v)
		if tc.ops != 0 {
			r.Ops = tc.ops
		}
		var u lsm.UnixRules
		p, _, err := toLSM(r, &u)
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
		if !reflect.DeepEqual(u, tc.unix) {
			t.Errorf("%s: %+v, want %+v", tc.spec, u, tc.unix)
		}
	}
	var u lsm.UnixRules
	if _, _, err := toLSM(rules.Rule{Ops: rules.OpNet, Verdict: rules.Allow, Object: rules.ObjectMatch{OwnListener: true}}, &u); err != nil || !u.OwnListeners {
		t.Errorf("own listeners: %v %+v", err, u)
	}
	if _, _, err := toLSM(rules.Rule{Ops: rules.OpNet, Verdict: rules.Deny, Object: rules.ObjectMatch{OwnListener: true}}, &u); !errors.Is(err, ErrUnsupported) {
		t.Errorf("deny own listeners: %v", err)
	}
	if _, _, err := toLSM(rules.Rule{Ops: rules.OpNet, Verdict: rules.Ask, Object: rules.ObjectMatch{OwnListener: true}}, &u); !errors.Is(err, ErrUnsupported) {
		t.Errorf("ask own listeners: %v", err)
	}
}

// TestNetStrict: every inet or abstract destination the monitor lets
// through, by a rule or a "once" answer, is granted to the thread.
func TestNetStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setup(t, k, false)
	if _, err := fx.m.Apply(rulesDecision(
		netRule(t, "tcp:192.0.2.0/24:443", rules.Allow),
		netRule(t, "192.0.2.5", rules.Ask),
		netRule(t, "unix:@x", rules.Allow),
	)); err != nil {
		t.Fatal(err)
	}
	lastGrant := func() lsm.NetGrant {
		t.Helper()
		k.mu.Lock()
		defer k.mu.Unlock()
		if len(k.netGrants) == 0 {
			t.Fatal("no grant")
		}
		return k.netGrants[len(k.netGrants)-1]
	}
	tcp := sock(t, unix.AF_INET, unix.SOCK_STREAM)
	fx.f.expect(t, fx.f.connect(tcp, sockaddrInet("192.0.2.7:443")), 0)
	want := lsm.InetDest{Addr: netip.MustParseAddrPort("192.0.2.7:443"), Proto: unix.IPPROTO_TCP}
	if g := lastGrant(); len(g.Inet) != 1 || g.Inet[0] != want {
		t.Errorf("grant by rule %+v", g)
	}

	id := fx.f.connect(tcp, sockaddrInet("192.0.2.5:443"))
	req := fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	want.Addr = netip.MustParseAddrPort("192.0.2.5:443")
	if g := lastGrant(); len(g.Inet) != 1 || g.Inet[0] != want {
		t.Errorf("grant once %+v", g)
	}

	us := sock(t, unix.AF_UNIX, unix.SOCK_STREAM)
	fx.f.expect(t, fx.f.connect(us, sockaddrUnix("@x")), 0)
	if g := lastGrant(); g.Abstract == nil || *g.Abstract != "x" || g.Inet != nil {
		t.Errorf("abstract grant %+v", g)
	}
}
