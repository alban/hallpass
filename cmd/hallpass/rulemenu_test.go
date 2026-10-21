// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
)

// fakeMenuTerm plays keys and lines, and records the overlays shown.
type fakeMenuTerm struct {
	height int // 0: 24
	keys   []byte
	lines  []func(text string) (string, bool)
	shown  [][]string
}

func (f *fakeMenuTerm) Height() int {
	if f.height == 0 {
		return 24
	}
	return f.height
}

func (f *fakeMenuTerm) Prompt(lines []string, _ string, _, _ time.Duration, _ <-chan struct{}, _ <-chan []string) byte {
	f.shown = append(f.shown, lines)
	if len(f.keys) == 0 {
		return 0
	}
	k := f.keys[0]
	f.keys = f.keys[1:]
	return k
}

func (f *fakeMenuTerm) ReadLine(lines []string, text string) (string, bool) {
	f.shown = append(f.shown, append(lines[:len(lines):len(lines)], text))
	if len(f.lines) == 0 {
		return "", false
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l(text)
}

func typed(s string) func(string) (string, bool) {
	return func(string) (string, bool) { return s, true }
}

func TestRulesMenu(t *testing.T) {
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := &session{cfg: sessionConfig{Defaults: defaults.NewLexical("/root", "", nil, nil)}, m: m}
	ruleID := func() string {
		_, rs, _ := m.Snapshot()
		if len(rs) != 1 {
			t.Fatalf("rules: %v", rs)
		}
		return strconv.FormatUint(rs[0].ID, 10)
	}
	var edited string
	term := &fakeMenuTerm{
		keys: []byte("aeaaed\x1d"),
		lines: []func(string) (string, bool){
			typed("deny path /root/secret for 1h"), typed("secrets"),
			func(string) (string, bool) { return ruleID(), true },
			func(text string) (string, bool) { edited = text; return "deny path /root/secret/**", true },
			typed("allow path /"), typed(""),
			typed("not a rule"), typed(""),
			typed("999"),
			func(string) (string, bool) { return ruleID(), true },
		},
	}
	s.rulesMenu(term)

	if !strings.HasPrefix(edited, "deny path /root/secret for 59m") {
		t.Errorf("edit started from %q", edited)
	}
	var msgs []string
	for _, l := range term.shown {
		if len(l) > 1 && strings.Contains(l[len(l)-1], "[a] add") {
			msgs = append(msgs, strings.TrimSpace(l[len(l)-2]))
		}
	}
	// After: nothing, the add, the edit, the wide allow, the bad rule,
	// the bad ID, the delete.
	if len(msgs) != 7 || msgs[1] != "Done." || msgs[2] != "Done." ||
		!strings.Contains(msgs[3], `answering "always"`) || !strings.Contains(msgs[4], "Not changed:") ||
		msgs[5] != "Not changed: no rule 999" || msgs[6] != "Done." {
		t.Errorf("messages: %q", msgs)
	}
	listed := strings.Join(term.shown[len(term.shown)-2], "\n")
	if !strings.Contains(listed, "deny path /root/secret/**  (secrets)") {
		t.Errorf("edited rule not listed, or its label lost:\n%s", listed)
	}
	if _, rs, _ := m.Snapshot(); len(rs) != 0 {
		t.Errorf("rules left: %v", rs)
	}
}

func TestRulesMenuPages(t *testing.T) {
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	s := &session{cfg: sessionConfig{Defaults: defaults.NewLexical("/root", "", nil, nil)}, m: m}
	var d monitor.Decision
	for i := range 5 {
		d.AddRules = append(d.AddRules, rules.Rule{Verdict: rules.Deny, Ops: rules.OpAll, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/root/" + strconv.Itoa(i)}}})
	}
	if _, err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	term := &fakeMenuTerm{height: 6, keys: []byte("nnnppq")}
	s.rulesMenu(term)
	var got []string
	for _, l := range term.shown {
		got = append(got, l[0][strings.Index(l[0], "page"):][:8]+" "+strings.TrimSpace(l[1]))
	}
	want := []string{"page 1/3 1  deny path /root/0", "page 2/3 3  deny path /root/2", "page 3/3 5  deny path /root/4",
		"page 3/3 5  deny path /root/4", "page 2/3 3  deny path /root/2", "page 1/3 1  deny path /root/0"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("pages:\n%s", strings.Join(got, "\n"))
	}
}
