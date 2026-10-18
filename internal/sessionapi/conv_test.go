// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"testing"

	"github.com/alban/hallpass/internal/rules"
)

func TestNetRuleRoundTrip(t *testing.T) {
	for _, s := range []string{"all", "tcp:10.0.0.0/8:443", "[2001:db8::]/32", "*:53", "unix:/run/**", "unix:@x*"} {
		m, err := rules.ParseNet(s)
		if err != nil {
			t.Fatal(err)
		}
		r, err := fromPBRule(toPBRule(rules.Rule{Ops: rules.OpNet, Object: m}))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := r.Object.NetString(); got != s || r.Ops != rules.OpNet {
			t.Errorf("%s: round trip gives %q ops %b", s, got, r.Ops)
		}
	}
	own, err := fromPBRule(toPBRule(rules.Rule{Ops: rules.OpNet, Object: rules.ObjectMatch{OwnListener: true}}))
	if err != nil || !own.Object.OwnListener {
		t.Errorf("own listener: %+v %v", own, err)
	}
}
