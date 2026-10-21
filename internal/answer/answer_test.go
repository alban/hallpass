// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package answer

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/programs"
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
	if r.Op != "connect to" || r.Path != "127.0.0.1:80" || r.Detail != "tcp" || r.Scope != r.Path || r.Never != r.Scope || r.Note != OwnListenerNote {
		t.Errorf("inet: %+v", r)
	}
	r = Request(p, &monitor.Request{Op: rules.OpSend, Objects: []rules.Object{{Unix: &rules.UnixObject{Abstract: true, Name: "x"}}}}, 0)
	if r.Op != "send to" || r.Path != "unix @x" || r.Scope != r.Path || r.Note != "" {
		t.Errorf("unix: %+v", r)
	}
}

// TestNetAnswers: answers on a network request are address-only.
func TestNetAnswers(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	obj := rules.Object{Inet: &rules.InetObject{Proto: 6, Addr: netip.MustParseAddrPort("[::1]:443")}}
	var d monitor.Decision
	grant(p, &d, nil, rules.OpAll, obj, time.Time{})
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
	grant(p, &d, nil, rules.OpAll, obj, time.Time{})
	if len(d.AddRules) != 1 || d.AddRules[0].Object.Path.Path != "/opt/tool" || !d.AddRules[0].Object.Path.Tree {
		t.Fatalf("got %+v", d.AddRules)
	}

	// A permanent grant on the folder already covers a temp one.
	rs := []rules.Rule{{ID: 3, Ops: rules.OpAll, Verdict: rules.Allow, Object: d.AddRules[0].Object}}
	d = monitor.Decision{}
	grant(p, &d, rs, rules.OpAll, obj, time.Now().Add(time.Hour))
	if len(d.AddRules)+len(d.RemoveRules) != 0 {
		t.Errorf("shrinking grant: %+v", d)
	}
	// A permanent grant replaces a temp one.
	rs[0].Expires = time.Now().Add(time.Hour)
	grant(p, &d, rs, rules.OpAll, obj, time.Time{})
	if len(d.RemoveRules) != 1 || d.RemoveRules[0] != 3 || len(d.AddRules) != 1 {
		t.Errorf("got %+v", d)
	}
}

func advReq(p string, a monitor.Advance) *monitor.Request {
	r := pathReq(p)
	r.Op = rules.OpFiles
	r.Advance = &a
	return r
}

func TestRequestAdvance(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	r := Request(p, advReq("/root/w", monitor.Advance{Tree: true, For: time.Minute, Reason: "why"}), 0)
	if !r.Advance || r.Op != "write" || r.Path != "/root/w/**" || r.For != time.Minute || r.Reason != "why" || r.Scope != "" {
		t.Errorf("got %+v", r)
	}
	if r := Request(p, advReq("/", monitor.Advance{Tree: true}), 0); r.Path != "/**" {
		t.Errorf("root: %+v", r)
	}
	exec := advReq("/opt/tool", monitor.Advance{Tree: true, Writable: true})
	exec.Op = rules.OpExec
	if r := Request(p, exec, 0); !r.Advance || r.Op != "exec" || r.Path != "/opt/tool/**" || !strings.Contains(r.Warn, "writable") {
		t.Errorf("exec: %+v", r)
	}
	dest, err := rules.ParseNet("tcp:[2001:db8::1]:443")
	if err != nil {
		t.Fatal(err)
	}
	conn := &monitor.Request{Op: rules.OpNet, Advance: &monitor.Advance{Net: dest, Reason: "push"}}
	if r := Request(p, conn, 0); !r.Advance || r.Op != "connect to" || r.Path != "tcp:[2001:db8::1]:443" || r.Reason != "push" || r.Warn != "" {
		t.Errorf("connect: %+v", r)
	}
}

// TestApplyGrantNet: the grant of a request for network destinations is
// a network rule in the advance set.
func TestApplyGrantNet(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	dest, err := rules.ParseNet("udp:9.9.9.9:53")
	if err != nil {
		t.Fatal(err)
	}
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	req := &monitor.Request{Op: rules.OpNet, Advance: &monitor.Advance{Net: dest}}
	if err := Apply(m, p, req, ui.AnswerGrant, nil, "test"); !errors.Is(err, monitor.ErrClosed) {
		t.Errorf("Apply: %v, want ErrClosed", err)
	}
	_, rs, _ := m.Snapshot()
	if len(rs) != 1 || rs[0].Ops != rules.OpNet || rs[0].Set != monitor.AdvanceSet || rs[0].Object.NetString() != "udp:9.9.9.9:53" || !rs[0].Expires.IsZero() {
		t.Fatalf("rules %+v", rs)
	}
	rs = append(rs,
		rules.Rule{Ops: rules.OpExec, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/opt/t"}}},
		rules.Rule{Ops: rules.OpAll, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/w/", Tree: true}}})
	if got := Released(rs); got != "connect to udp:9.9.9.9:53, exec /opt/t, write /w/**" {
		t.Errorf("released %q", got)
	}
}

// TestApplyGrant: "grant" adds the rule asked for; other allows deny.
func TestApplyGrant(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	for _, tc := range []struct {
		name string
		adv  monitor.Advance
		a    ui.Answer
		want *rules.PathMatch
	}{
		{"tree", monitor.Advance{Tree: true, For: time.Hour}, ui.AnswerGrant, &rules.PathMatch{Path: "/w", Tree: true}},
		{"exact", monitor.Advance{}, ui.AnswerGrant, &rules.PathMatch{Path: "/w"}},
		{"always", monitor.Advance{Tree: true}, ui.AnswerAllowAlways, nil},
		{"never", monitor.Advance{Tree: true}, ui.AnswerNever, nil},
		{"timeout", monitor.Advance{Tree: true}, ui.AnswerTimeout, nil},
	} {
		m, err := monitor.New(monitor.Config{})
		if err != nil {
			t.Fatal(err)
		}
		before := time.Now()
		if err := Apply(m, p, advReq("/w", tc.adv), tc.a, nil, "test"); !errors.Is(err, monitor.ErrClosed) {
			t.Errorf("%s: Apply: %v, want ErrClosed", tc.name, err)
		}
		_, rs, _ := m.Snapshot()
		m.Close()
		if tc.want == nil {
			if len(rs) != 0 {
				t.Errorf("%s: rules %+v", tc.name, rs)
			}
			continue
		}
		if len(rs) != 1 || rs[0].Verdict != rules.Allow || rs[0].Ops != rules.OpAll || rs[0].Set != monitor.AdvanceSet || rs[0].Object.Path.Path != tc.want.Path || rs[0].Object.Path.Tree != tc.want.Tree {
			t.Fatalf("%s: rules %+v", tc.name, rs)
		}
		if e := rs[0].Expires; (tc.adv.For == 0) != e.IsZero() || (!e.IsZero() && e.Before(before.Add(tc.adv.For))) {
			t.Errorf("%s: expires %v", tc.name, e)
		}
	}
}

// TestExecAnswers: answers on an exec cover running that program only.
func TestExecAnswers(t *testing.T) {
	p := defaults.NewLexical("/root", "", nil, nil)
	obj := rules.Object{Path: &rules.PathObject{Path: "/opt/tool/bin/run"}}
	var d monitor.Decision
	// A file grant on the folder does not cover running a program there.
	rs := []rules.Rule{{ID: 3, Ops: rules.OpAll, Verdict: rules.Allow, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/opt/tool/bin/run"}}}}
	grant(p, &d, rs, answerOps(rules.OpExec), obj, time.Time{})
	if len(d.AddRules) != 1 || len(d.RemoveRules) != 0 {
		t.Fatalf("got %+v", d)
	}
	r := d.AddRules[0]
	if r.Ops != rules.OpExec || r.Object.Path.Path != "/opt/tool/bin/run" || r.Object.Path.Tree {
		t.Errorf("exec grant: %+v %+v", r, r.Object.Path)
	}
	if answerOps(rules.OpWrite) != rules.OpAll {
		t.Errorf("write answers: %v", answerOps(rules.OpWrite))
	}
	req := Request(p, &monitor.Request{Op: rules.OpExec, Objects: []rules.Object{obj}}, 0)
	if req.Scope != "/opt/tool/bin/run" || req.Op != "exec" || req.Group != "" {
		t.Errorf("request: %+v", req)
	}
}

// TestGroupAnswer: "group" allows every program of the group of the one
// asked about, except those already allowed for good.
func TestGroupAnswer(t *testing.T) {
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	p := defaults.NewLexical("/root", "", nil, nil)
	p.SetGroups([]programs.Group{{Name: "@coreutils", Members: []string{"/opt/cu/cat", "/opt/cu/ls", "/opt/cu/cp"}}})
	obj := rules.Object{Path: &rules.PathObject{Path: "/opt/cu/ls"}}
	req := &monitor.Request{ID: 9, Op: rules.OpExec, Objects: []rules.Object{obj}}
	if got := Request(p, req, 0).Group; got != "@coreutils (cat, ls, cp: 3 programs)" {
		t.Errorf("group %q", got)
	}
	cat := rules.Rule{ID: 1, Ops: rules.OpExec, Verdict: rules.Allow, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/opt/cu/cat"}}}
	if err := Apply(m, p, req, ui.AnswerAllowGroup, []rules.Rule{cat}, "test"); !errors.Is(err, monitor.ErrClosed) {
		t.Fatalf("Apply: %v", err)
	}
	_, rs, _ := m.Snapshot()
	var got []string
	for _, r := range rs {
		if r.Ops != rules.OpExec || r.Verdict != rules.Allow || r.Label != "@coreutils" || r.Object.Path.Tree {
			t.Errorf("rule %+v", r)
		}
		got = append(got, r.Object.Path.Path)
	}
	if strings.Join(got, " ") != "/opt/cu/ls /opt/cu/cp" {
		t.Errorf("rules for %q", got)
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
