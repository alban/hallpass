// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
	"time"
)

func TestParseSpec(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in, spec string
		ops      Op
		expires  time.Duration
	}{
		{in: "allow path /home/u/src/**", spec: "allow path /home/u/src/**", ops: OpAll},
		{in: "  deny path /etc/passwd  ", spec: "deny path /etc/passwd", ops: OpAll},
		{in: "allow path /**", spec: "allow path /**", ops: OpAll},
		{in: "allow path /a/../b/", spec: "allow path /b", ops: OpAll},
		{in: "ask path /x y/z for 10m", spec: "ask path /x y/z", ops: OpAll, expires: 10 * time.Minute},
		{in: "allow path /d/for x", spec: "allow path /d/for x", ops: OpAll},
		{in: "allow exec /usr/bin/git", spec: "allow exec /usr/bin/git", ops: OpExec},
		{in: "deny exec /opt/bin/** for 1h", spec: "deny exec /opt/bin/**", ops: OpExec, expires: time.Hour},
		{in: "allow net tcp:1.2.3.4:443", spec: "allow net tcp:1.2.3.4:443", ops: OpNet},
		{in: "deny net all", spec: "deny net all", ops: OpNet},
		{in: "allow net own-listeners", spec: "allow net own-listeners", ops: OpNet},
		{in: "ask net unix:@name*", spec: "ask net unix:@name*", ops: OpNet},
		{in: "allow proc oom_score_adj chrome", spec: "allow proc oom_score_adj chrome", ops: OpAll},
		{in: "allow proc oom_score_adj Web Content", spec: "allow proc oom_score_adj Web Content", ops: OpAll},
		{in: "deny unknown", spec: "deny unknown", ops: OpAll},
	} {
		r, err := ParseSpec(tc.in, now)
		if err != nil {
			t.Errorf("ParseSpec(%q): %v", tc.in, err)
			continue
		}
		if got := r.Spec(); got != tc.spec {
			t.Errorf("ParseSpec(%q).Spec() = %q, want %q", tc.in, got, tc.spec)
		}
		if r.Ops != tc.ops {
			t.Errorf("ParseSpec(%q).Ops = %#x, want %#x", tc.in, r.Ops, tc.ops)
		}
		var want time.Time
		if tc.expires != 0 {
			want = now.Add(tc.expires)
		}
		if !r.Expires.Equal(want) {
			t.Errorf("ParseSpec(%q).Expires = %v, want %v", tc.in, r.Expires, want)
		}
	}
	for _, in := range []string{
		"", "allow", "maybe path /x", "allow path", "allow path rel/x", "allow exec ~/bin/x",
		"allow net nope:1.2.3.4:x", "allow proc", "allow proc a/b c", "deny unknown x",
		"allow file /x", "allow path /x for -1m",
	} {
		if r, err := ParseSpec(in, now); err == nil {
			t.Errorf("ParseSpec(%q) = %v, want an error", in, r)
		}
	}
}

func TestRuleString(t *testing.T) {
	r := Rule{ID: 7, Ops: OpExec, Verdict: Ask, Object: ObjectMatch{Path: &PathMatch{Path: "/usr/bin/curl"}}, Set: "implicit"}
	if got, want := r.String(), `rule 7 (ask exec /usr/bin/curl) in set "implicit"`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	r.Expires = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	if got := r.String(); !strings.HasSuffix(got, " until 2026-10-20T12:00:00Z") {
		t.Errorf("String() = %q", got)
	}
}

func TestEditSpec(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	r := Rule{Ops: OpAll, Object: ObjectMatch{Path: &PathMatch{Path: "/data", Tree: true}}, Label: "@build"}
	for _, tc := range []struct {
		left time.Duration
		want string
	}{
		{0, "allow path /data/**"},
		{-time.Minute, "allow path /data/**"},
		{90*time.Second + 500*time.Millisecond, "allow path /data/** for 90s"},
		{10*time.Minute - time.Second, "allow path /data/** for 9m"},
	} {
		r.Expires = time.Time{}
		if tc.left != 0 {
			r.Expires = now.Add(tc.left)
		}
		if got := r.EditSpec(now); got != tc.want {
			t.Errorf("EditSpec, %v left = %q, want %q", tc.left, got, tc.want)
		}
	}
	if l := r.EditLabel(); l != "" {
		t.Errorf("EditLabel() = %q for a group's rule", l)
	}
	r.Label = "SSH keys"
	if l := r.EditLabel(); l != "SSH keys" {
		t.Errorf("EditLabel() = %q", l)
	}
}
