// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package answer

import (
	"errors"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/rules"
)

func mustSpec(t *testing.T, s string, now time.Time) rules.Rule {
	t.Helper()
	r, err := rules.ParseSpec(s, now)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGrantable(t *testing.T) {
	p := defaults.NewLexical("/home/u", "", nil, []string{"/opt/secret"})
	now := time.Now()
	for _, tc := range []struct {
		spec string
		want bool
	}{
		{"allow path /home/u/src/**", true},
		{"allow path /home/u/src/proj/**", true},
		{"allow path /home/u/src/proj/main.go", true},
		{"allow path /home/u/.cache/go-build/**", true},
		{"allow path /home/u/.cache/**", true}, // what "always" on ~/.cache/f gives
		{"allow path /home/u/.config/**", false},
		{"allow path /home/u/**", false},
		{"allow path /home/**", false},
		{"allow path /home/u/.bashrc", false},
		{"allow path /**", false},
		{"allow path /opt/**", false}, // holds a denied path
		{"allow path /etc/**", true},
		{"allow path /etc/hosts for 10m", true},
		{"allow exec /usr/bin/git", true},
		{"allow exec /usr/bin/**", false},
		{"allow proc oom_score_adj chrome", true},
		{"allow net tcp:1.2.3.4:443", true},
		{"allow net [2001:db8::1]:22", true},
		{"allow net 1.2.3.4", false},
		{"allow net 1.2.3.0/24:443", false},
		{"allow net 1.2.3.4:1-1024", false},
		{"allow net *:443", false},
		{"allow net unix:/run/x.sock", true},
		{"allow net unix:/run/**", false},
		{"allow net unix:@name", true},
		{"allow net unix:@name*", false},
		{"allow net own-listeners", false},
		{"allow net all", false},
		{"allow unknown", false},
	} {
		if got := Grantable(p, mustSpec(t, tc.spec, now)); got != tc.want {
			t.Errorf("Grantable(%s) = %v, want %v", tc.spec, got, tc.want)
		}
	}
	r := mustSpec(t, "allow exec /usr/bin/git", now)
	r.Object.Path.Args = []string{"log"}
	if Grantable(p, r) {
		t.Errorf("Grantable(exec with args)")
	}
	r = mustSpec(t, "allow path /etc/hosts", now)
	r.Ops |= rules.OpExec
	if Grantable(p, r) {
		t.Errorf("Grantable(file and exec ops)")
	}
}

func TestCheckRules(t *testing.T) {
	p := defaults.NewLexical("/home/u", "", nil, nil)
	now := time.Now()
	all := mustSpec(t, "allow net all", now)
	ask := mustSpec(t, "ask path /home/u/.ssh/**", now)
	for _, tc := range []struct {
		name    string
		add, rm []rules.Rule
		ok, tOK bool // CheckRules, CheckTighten
	}{
		{name: "deny", add: []rules.Rule{mustSpec(t, "deny path /**", now)}, ok: true, tOK: true},
		{name: "grantable", add: []rules.Rule{mustSpec(t, "allow net 1.2.3.4:443", now)}, ok: true},
		{name: "wide", add: []rules.Rule{mustSpec(t, "allow net 1.2.3.0/24:443", now)}},
		{name: "narrowed", rm: []rules.Rule{all}, add: []rules.Rule{mustSpec(t, "allow net 1.2.3.0/24:443", now)}, ok: true, tOK: true},
		{name: "remove an allow", rm: []rules.Rule{all}, ok: true, tOK: true},
		{name: "remove an ask", rm: []rules.Rule{ask}, ok: true},
	} {
		if err := CheckRules(p, tc.add, tc.rm); (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrTooWide)) {
			t.Errorf("%s: CheckRules: %v", tc.name, err)
		}
		if err := CheckTighten(tc.add, tc.rm); (err == nil) != tc.tOK || (err != nil && !errors.Is(err, ErrTooWide)) {
			t.Errorf("%s: CheckTighten: %v", tc.name, err)
		}
	}
}
