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
	if a := out.GetAdvance(); a.GetDest() != "" || a.GetWritable() {
		t.Errorf("files: %v", a)
	}
	dest, err := rules.ParseNet("tcp:10.0.0.0/8:443")
	if err != nil {
		t.Fatal(err)
	}
	net := toPBRequest(&monitor.Request{Op: rules.OpNet, Advance: &monitor.Advance{Net: dest}}, nil)
	if net.GetAdvance().GetDest() != "tcp:10.0.0.0/8:443" || len(net.GetObjects()) != 0 {
		t.Errorf("net: %v", net)
	}
	req.Op, req.Advance.Writable = rules.OpExec, true
	if a := toPBRequest(req, nil).GetAdvance(); !a.GetWritable() {
		t.Errorf("exec: %v", a)
	}
	d, err := fromPBDecision(&pb.Decision{TimedOut: true})
	if err != nil || !d.TimedOut {
		t.Errorf("decision %+v %v", d, err)
	}
}
