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
	work := mustSpec(t, "allow write /work/**", now)
	secret := mustSpec(t, "allow write /work/secret/**", now)
	askSecret := mustSpec(t, "ask write /work/secret/**", now)
	askWork := mustSpec(t, "ask write /work/**", now)
	askNet := mustSpec(t, "ask connect 10.0.0.0/24:22", now)
	key := mustSpec(t, "allow write /work/secret/key", now)
	for _, tc := range []struct {
		name          string
		add, rm, next []rules.Rule
		ok, tOK       bool // CheckRules, CheckTighten
	}{
		{name: "deny", add: []rules.Rule{mustSpec(t, "deny write /**", now)}, ok: true, tOK: true},
		{name: "grantable", add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.4:443", now)}, ok: true},
		{name: "wide", add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.0/24:443", now)}},
		{name: "narrowed", rm: []rules.Rule{all}, add: []rules.Rule{mustSpec(t, "allow connect 1.2.3.0/24:443", now)}, ok: true, tOK: true},
		{name: "remove an allow", rm: []rules.Rule{all}, ok: true, tOK: true},
		{name: "remove an ask", rm: []rules.Rule{ask}, ok: true},
		// The wider allow lost to the ask rule, the narrower one wins;
		// answering "always" to the ask could give it.
		{name: "narrowed past an ask", rm: []rules.Rule{work}, add: []rules.Rule{work, key}, next: []rules.Rule{askSecret, work, key}, ok: true},
		{name: "narrowed past a network ask", rm: []rules.Rule{all}, add: []rules.Rule{mustSpec(t, "allow connect 10.0.0.1:22", now)}, next: []rules.Rule{askNet}, ok: true},
		{name: "narrowed beside an ask", rm: []rules.Rule{work}, add: []rules.Rule{mustSpec(t, "allow write /work/other", now)}, next: []rules.Rule{askSecret}, ok: true, tOK: true},
		// The wider allow already won over the ask rule.
		{name: "narrowed under a shallower ask", rm: []rules.Rule{secret}, add: []rules.Rule{key}, next: []rules.Rule{askWork, key}, ok: true, tOK: true},
	} {
		if err := CheckRules(p, tc.add, tc.rm, tc.next); (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrTooWide)) {
			t.Errorf("%s: CheckRules: %v", tc.name, err)
		}
		if err := CheckTighten(tc.add, tc.rm, tc.next); (err == nil) != tc.tOK || (err != nil && !errors.Is(err, ErrTooWide)) {
			t.Errorf("%s: CheckTighten: %v", tc.name, err)
		}
	}
}

// TestCheckTightenEval checks CheckTighten against rules.Eval: an edit it
// accepts allows nothing more.
func TestCheckTightenEval(t *testing.T) {
	now := time.Now()
	before := []rules.Rule{
		mustSpec(t, "allow write /work/**", now),
		mustSpec(t, "ask write /work/secret/**", now),
	}
	before[0].ID, before[1].ID = 1, 2
	objs := []string{"/work/a", "/work/secret/key", "/work/secret/x/y"}
	for _, add := range []string{"allow write /work/secret/key", "allow write /work/secret/x/**", "allow write /work/a", "allow write /work/secret/**"} {
		r := mustSpec(t, add, now)
		r.ID = 3
		next := []rules.Rule{before[1], r}
		err := CheckTighten([]rules.Rule{r}, before[:1], next)
		for _, p := range objs {
			obj := rules.Object{Path: &rules.PathObject{Path: p}}
			v0, _, ok0 := rules.Eval(before, rules.OpWrite, obj, now)
			v1, _, ok1 := rules.Eval(next, rules.OpWrite, obj, now)
			wider := ok1 && v1 == rules.Allow && !(ok0 && v0 == rules.Allow)
			if wider && err == nil {
				t.Errorf("%s accepted, but allows %s", add, p)
			}
		}
	}
}
