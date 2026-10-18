// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package answer

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
)

func pathReq(p string) *monitor.Request {
	return &monitor.Request{
		ID:      1,
		Op:      rules.OpWrite,
		Objects: []rules.Object{{Path: &rules.PathObject{Path: p}}},
		Subject: rules.Subject{Chain: []rules.Task{{TID: 7, Comm: "sh", Exe: "/bin/sh"}, {Comm: "a"}, {Comm: "b"}}},
	}
}

func TestRequest(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	r := Request(p, pathReq("/root/.ssh/id"), 2)
	if r.Path != "/root/.ssh/id" || r.Scope != "/root/.ssh" || r.Warn == "" || r.Waiting != 2 || r.PID != 7 || len(r.Parents) != 2 {
		t.Errorf("got %+v", r)
	}
	r = Request(p, &monitor.Request{Objects: []rules.Object{{Unknown: errors.New("EFAULT")}}}, 0)
	r = Request(p, &monitor.Request{Op: rules.OpConnect, Objects: []rules.Object{{Inet: &rules.InetObject{Proto: 6, Addr: netip.MustParseAddrPort("127.0.0.1:80"), OwnListener: true}}}}, 0)
	if r.Op != "connect" || r.Path != "tcp 127.0.0.1:80" || r.Scope != "127.0.0.1:80" || r.Never != r.Scope || r.Note != OwnListenerNote {
		t.Errorf("inet: %+v", r)
	}
	r = Request(p, &monitor.Request{Op: rules.OpSend, Objects: []rules.Object{{Unix: &rules.UnixObject{Abstract: true, Name: "x"}}}}, 0)
	if r.Op != "send" || r.Path != "unix @x" || r.Scope != r.Path || r.Note != "" {
		t.Errorf("unix: %+v", r)
	}
}

// TestNetAnswers: answers on a network request are address-only.
func TestNetAnswers(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	obj := rules.Object{Inet: &rules.InetObject{Proto: 6, Addr: netip.MustParseAddrPort("[::1]:443")}}
	var d monitor.Decision
	grant(p, &d, nil, obj, time.Time{})
	if len(d.AddRules) != 1 || d.AddRules[0].Object.NetString() != "[::1]:443" {
		t.Fatalf("grant: %+v", d.AddRules)
	}
	if m := exact(obj); m.NetString() != "[::1]:443" {
		t.Errorf("never: %+v", m)
	}
	u := rules.Object{Unix: &rules.UnixObject{Path: "/run/x.sock"}}
	if m := exact(u); m.NetString() != "unix:/run/x.sock" {
		t.Errorf("never unix: %+v", m)
	}
}

func TestGrant(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	obj := rules.Object{Path: &rules.PathObject{Path: "/opt/tool/lib/f"}}
	var d monitor.Decision
	grant(p, &d, nil, obj, time.Time{})
	if len(d.AddRules) != 1 || d.AddRules[0].Object.Path.Path != "/opt/tool" || !d.AddRules[0].Object.Path.Tree {
		t.Fatalf("got %+v", d.AddRules)
	}

	// A permanent grant on the folder already covers a temp one.
	rs := []rules.Rule{{ID: 3, Verdict: rules.Allow, Object: d.AddRules[0].Object}}
	d = monitor.Decision{}
	grant(p, &d, rs, obj, time.Now().Add(time.Hour))
	if len(d.AddRules)+len(d.RemoveRules) != 0 {
		t.Errorf("shrinking grant: %+v", d)
	}
	// A permanent grant replaces a temp one.
	rs[0].Expires = time.Now().Add(time.Hour)
	grant(p, &d, rs, obj, time.Time{})
	if len(d.RemoveRules) != 1 || d.RemoveRules[0] != 3 || len(d.AddRules) != 1 {
		t.Errorf("got %+v", d)
	}
}

func TestApplyClosed(t *testing.T) {
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	p := defaults.NewLexical("/root", "", nil, nil)
	err = Apply(m, p, pathReq("/opt/tool/f"), ui.AnswerNever, nil, "test")
	if !errors.Is(err, monitor.ErrClosed) {
		t.Fatalf("Apply: %v, want ErrClosed", err)
	}
	// The rule of "never" is kept.
	_, rs, _ := m.Snapshot()
	if len(rs) != 1 || rs[0].Verdict != rules.Deny || rs[0].Object.Path.Path != "/opt/tool/f" || rs[0].Object.Path.Tree {
		t.Errorf("rules: %+v", rs)
	}
	if _, _, err := Find(m, 1); !errors.Is(err, monitor.ErrClosed) {
		t.Errorf("Find: %v", err)
	}
}
