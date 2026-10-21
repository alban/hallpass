// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rulepb

import (
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
)

func TestNetRuleRoundTrip(t *testing.T) {
	for _, s := range []string{"all", "tcp:10.0.0.0/8:443", "[2001:db8::]/32", "*:53", "unix:/run/**", "unix:@x*"} {
		m, err := rules.ParseNet(s)
		if err != nil {
			t.Fatal(err)
		}
		r, err := From(To(rules.Rule{Ops: rules.OpNet, Object: m}))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := r.Object.NetString(); got != s || r.Ops != rules.OpNet {
			t.Errorf("%s: round trip gives %q ops %b", s, got, r.Ops)
		}
	}
	own, err := From(To(rules.Rule{Ops: rules.OpNet, Object: rules.ObjectMatch{OwnListener: true}}))
	if err != nil || !own.Object.OwnListener {
		t.Errorf("own listener: %+v %v", own, err)
	}
}

func TestParse(t *testing.T) {
	now := time.Now()
	specs := []string{
		"allow write /w/**", "deny exec /usr/bin/curl", "ask connect tcp:10.0.0.1:443",
		"allow proc environ bash", "deny connect unix:@x", "allow write /a for 1h",
	}
	got, err := Parse(specs, "web", now)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range got {
		want := specs[i]
		if i == len(specs)-1 {
			want = "allow write /a"
			if !r.GetExpires().AsTime().Equal(now.Add(time.Hour)) {
				t.Errorf("expires %v", r.GetExpires().AsTime())
			}
		}
		if s := r.GetSpec(); s != want || r.GetLabel() != "web" {
			t.Errorf("%q: got %q label %q", specs[i], s, r.GetLabel())
		}
	}
	if _, err := Parse([]string{"allow write rel"}, "", now); err == nil {
		t.Error("relative path parsed")
	}
}
