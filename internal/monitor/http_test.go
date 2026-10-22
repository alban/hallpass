// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
)

// TestDecideHTTP: a proxied request no rule decides is asked about like
// any other, and answered; a rule decides without asking; a request
// whose connection closes is closed.
func TestDecideHTTP(t *testing.T) {
	fx := setup(t, nil, false)
	now := time.Now()
	r, err := rules.ParseSpec("deny http POST https://api.example.test/**", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.m.Apply(rulesDecision(r)); err != nil {
		t.Fatal(err)
	}
	subject := rules.Subject{Chain: []rules.Task{{PID: 42, TID: 42, Comm: "gh"}}}
	if ok, why := fx.m.DecideHTTP(t.Context(), subject, rules.HTTPObject{Method: "POST", Host: "api.example.test", Path: "/x"}); ok || why == "" {
		t.Errorf("denied by a rule: %v %q", ok, why)
	}
	done := make(chan bool)
	go func() {
		ok, _ := fx.m.DecideHTTP(t.Context(), subject, rules.HTTPObject{Method: "GET", Host: "api.example.test", Path: "/x"})
		done <- ok
	}()
	req := fx.next(t, opened).Opened
	if req.Op != rules.OpHTTP || req.Objects[0].HTTP == nil || req.Objects[0].HTTP.URL() != "https://api.example.test/x" || req.Subject.Chain[0].Comm != "gh" {
		t.Fatalf("request %+v", req)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	if !<-done {
		t.Error("allowed request denied")
	}
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		ok, _ := fx.m.DecideHTTP(ctx, subject, rules.HTTPObject{Method: "GET", Host: "api.example.test", Path: "/y"})
		done <- ok
	}()
	fx.next(t, opened)
	cancel()
	if <-done {
		t.Error("allowed after its connection closed")
	}
	if c := fx.next(t, isClosed).Closed; !c.Why.Died {
		t.Errorf("closed %+v, want died", c)
	}
}
