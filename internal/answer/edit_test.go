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
		{"allow write /home/u/src/**", true},
		{"allow write /home/u/src/proj/**", true},
		{"allow write /home/u/src/proj/main.go", true},
		{"allow write /home/u/.cache/go-build/**", true},
		{"allow write /home/u/.cache/**", true}, // what "always" on ~/.cache/f gives
		{"allow write /home/u/.config/**", false},
		{"allow write /home/u/**", false},
		{"allow write /home/**", false},
		{"allow write /home/u/.bashrc", false},
		{"allow write /**", false},
		{"allow write /opt/**", false}, // holds a denied path
		{"allow write /etc/**", true},
		{"allow write /etc/hosts for 10m", true},
		{"allow exec /usr/bin/git", true},
		{"allow exec /usr/bin/**", false},
		{"allow proc oom_score_adj chrome", true},
		{"allow connect tcp:1.2.3.4:443", true},
		{"allow connect [2001:db8::1]:22", true},
		{"allow connect 1.2.3.4", false},
		{"allow connect 1.2.3.0/24:443", false},
		{"allow connect 1.2.3.4:1-1024", false},
		{"allow connect *:443", false},
		{"allow connect unix:/run/x.sock", true},
		{"allow connect unix:/run/**", false},
		{"allow connect unix:@name", true},
		{"allow connect unix:@name*", false},
		{"allow connect own-listeners", false},
		{"allow connect all", false},
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
	r = mustSpec(t, "allow write /etc/hosts", now)
	r.Ops |= rules.OpExec
	if Grantable(p, r) {
		t.Errorf("Grantable(file and exec ops)")
	}
}

func TestCheckRules(t *testing.T) {
	p := defaults.NewLexical("/home/u", "", nil, nil)
	now := time.Now()
	all := mustSpec(t, "allow connect all", now)
	ask := mustSpec(t, "ask write /home/u/.ssh/**", now)
	for _, tc := range []struct {
		name    string
		add, rm []rules.Rule
		ok, tOK bool // CheckRules, CheckTighten
	}{
		{name: "deny", add: []rules.Rule{mustSpec(t, "deny write /**", now)}, ok: true, tOK: true},
		{name: "grantable", add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.4:443", now)}, ok: true},
		{name: "wide", add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.0/24:443", now)}},
		{name: "narrowed", rm: []rules.Rule{all}, add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.0/24:443", now)}, ok: true, tOK: true},
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
