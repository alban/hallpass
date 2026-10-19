// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"testing"
	"time"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
)

func TestAdvanceConv(t *testing.T) {
	req := &monitor.Request{
		Op:      rules.OpFiles,
		Objects: []rules.Object{{Path: &rules.PathObject{Path: "/w"}}},
		Advance: &monitor.Advance{Tree: true, For: time.Minute, Reason: "r"},
	}
	p := ToPBPrompt(ui.Request{Advance: true, Path: "/w/**", For: time.Minute, Reason: "r"})
	out := toPBRequest(req, p)
	if a := out.GetAdvance(); !a.GetTree() || a.GetFor().AsDuration() != time.Minute || a.GetReason() != "r" {
		t.Errorf("advance %v", a)
	}
	if !p.GetAdvance() || p.GetGrantFor().AsDuration() != time.Minute || p.GetReason() != "r" {
		t.Errorf("prompt %v", p)
	}
	req.Advance.For = 0
	if out := toPBRequest(req, nil); out.GetAdvance().GetFor() != nil {
		t.Errorf("for: %v", out.GetAdvance())
	}
	if p := ToPBPrompt(ui.Request{Advance: true}); p.GetGrantFor() != nil {
		t.Errorf("grant_for: %v", p)
	}
	d, err := fromPBDecision(&pb.Decision{TimedOut: true})
	if err != nil || !d.TimedOut {
		t.Errorf("decision %+v %v", d, err)
	}
}

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
