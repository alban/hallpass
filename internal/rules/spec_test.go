// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/netip"
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
		{in: "allow write /home/u/src/**", spec: "allow write /home/u/src/**", ops: OpAll},
		{in: "  deny write /etc/passwd  ", spec: "deny write /etc/passwd", ops: OpAll},
		{in: "allow write /**", spec: "allow write /**", ops: OpAll},
		{in: "allow write /a/../b/", spec: "allow write /b", ops: OpAll},
		{in: "ask write /x y/z for 10m", spec: "ask write /x y/z", ops: OpAll, expires: 10 * time.Minute},
		{in: "allow write /d/for x", spec: "allow write /d/for x", ops: OpAll},
		{in: "allow exec /usr/bin/git", spec: "allow exec /usr/bin/git", ops: OpExec},
		{in: "deny exec /opt/bin/** for 1h", spec: "deny exec /opt/bin/**", ops: OpExec, expires: time.Hour},
		{in: "allow connect tcp:1.2.3.4:443", spec: "allow connect tcp:1.2.3.4:443", ops: OpNet},
		{in: "deny connect all", spec: "deny connect all", ops: OpNet},
		{in: "allow connect own-listeners", spec: "allow connect own-listeners", ops: OpNet},
		{in: "ask connect unix:@name*", spec: "ask connect unix:@name*", ops: OpNet},
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
		"", "allow", "maybe write /x", "allow write", "allow write rel/x", "allow exec ~/bin/x",
		"allow connect nope:1.2.3.4:x", "allow proc", "allow proc a/b c", "deny unknown x",
		"allow file /x", "allow write /x for -1m",
		"deny exec /usr/bin/curl for 1d", "allow write /a for b/c", // not durations
		"allow path /x", "allow net all", // the old names
		"allow write /src/*.go", "allow write /src/**/x", "deny exec /usr/bin/py?", "allow write /a/[b]/**",
	} {
		if r, err := ParseSpec(in, now); err == nil {
			t.Errorf("ParseSpec(%q) = %v, want an error", in, r)
		}
	}
}

func TestParsePathMatch(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want PathMatch
		err  string
	}{
		{in: "/src", want: PathMatch{Path: "/src"}},
		{in: "/src/", want: PathMatch{Path: "/src"}},
		{in: "/src/../etc//x", want: PathMatch{Path: "/etc/x"}},
		{in: "/src/**", want: PathMatch{Path: "/src", Tree: true}},
		{in: "/src//**", want: PathMatch{Path: "/src", Tree: true}},
		{in: "/**", want: PathMatch{Path: "/", Tree: true}},
		{in: "/", want: PathMatch{Path: "/"}},
		{in: "", err: `"": not an absolute path`},
		{in: "**", err: `"**": not an absolute path`},
		{in: "src/**", err: `"src/**": not an absolute path`},
		{in: "/src/*.go", err: `"/src/*.go": only a trailing /** is supported`},
		{in: "/src/**/x", err: `"/src/**/x": only a trailing /** is supported`},
		{in: "/src/**/**", err: `"/src/**/**": only a trailing /** is supported`},
		{in: "/bin/py?", err: `"/bin/py?": only a trailing /** is supported`},
		{in: "/a/[b]", err: `"/a/[b]": only a trailing /** is supported`},
	} {
		got, err := ParsePathMatch(tc.in)
		switch {
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("ParsePathMatch(%q) = %v, %v, want error %s", tc.in, got, err, tc.err)
		case tc.err == "" && (err != nil || got.Path != tc.want.Path || got.Tree != tc.want.Tree):
			t.Errorf("ParsePathMatch(%q) = %v, %v, want %v", tc.in, got, err, tc.want)
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
		{0, "allow write /data/**"},
		{-time.Minute, "allow write /data/** for 1s"},
		{500 * time.Millisecond, "allow write /data/** for 1s"},
		{90*time.Second + 500*time.Millisecond, "allow write /data/** for 90s"},
		{10*time.Minute - time.Second, "allow write /data/** for 9m"},
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

// TestEditable checks that the rules built from objects, as answers and
// flags build them, read back from their EditSpec, and that the others are
// not editable.
func TestEditable(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	path := func(p string, tree bool) ObjectMatch { return ObjectMatch{Path: &PathMatch{Path: p, Tree: tree}} }
	inet := func(p string, lo, hi uint16) ObjectMatch {
		return ObjectMatch{Inet: &InetMatch{Proto: 6, Prefix: netip.MustParsePrefix(p), PortLo: lo, PortHi: hi}}
	}
	for _, tc := range []struct {
		name string
		r    Rule
		want bool
	}{
		{"file", Rule{Ops: OpAll, Object: path("/home/u/x", false)}, true},
		{"tree", Rule{Ops: OpAll, Object: path("/home/u", true), Verdict: Deny}, true},
		{"files only", Rule{Ops: OpFiles, Object: path("/home/u/x", false)}, true},
		{"root tree", Rule{Ops: OpAll, Object: path("/", true)}, true},
		{"exec", Rule{Ops: OpExec, Object: path("/usr/bin/git", false), Expires: now.Add(time.Hour)}, true},
		{"expiring", Rule{Ops: OpAll, Object: path("/x", false), Expires: now.Add(300 * time.Millisecond)}, true},
		{"inet", Rule{Ops: OpNet, Object: inet("1.2.3.4/32", 443, 443)}, true},
		{"inet6", Rule{Ops: OpNet, Object: inet("2001:db8::1/128", 22, 22), Verdict: Ask}, true},
		{"unix", Rule{Ops: OpNet, Object: ObjectMatch{Unix: &UnixMatch{Path: "/run/x.sock"}}}, true},
		{"abstract", Rule{Ops: OpNet, Object: ObjectMatch{Unix: &UnixMatch{Abstract: true, Name: "bus"}}}, true},
		{"all", Rule{Ops: OpNet, Object: ObjectMatch{AnyNet: true}, Verdict: Deny}, true},
		{"proc", Rule{Ops: OpAll, Object: ObjectMatch{Proc: &ProcMatch{Name: "oom_score_adj", Comm: "Web Content"}}}, true},
		{"unknown", Rule{Ops: OpAll, Object: ObjectMatch{Unknown: true}, Verdict: Deny}, true},

		{"a file named **", Rule{Ops: OpAll, Object: path("/home/u/**", false), Verdict: Deny}, false},
		{"a glob", Rule{Ops: OpAll, Object: path("/home/u/*.go", false)}, false},
		{"for in a path", Rule{Ops: OpAll, Object: path("/x for 1h", false), Verdict: Deny}, false},
		{"newline", Rule{Ops: OpAll, Object: path("/x\nallow write /**", false), Verdict: Deny}, false},
		{"trailing space", Rule{Ops: OpExec, Object: path("/bin/x ", false)}, false},
		{"exec and write", Rule{Ops: OpAll | OpExec, Object: path("/bin/x", false)}, false},
		{"write only", Rule{Ops: OpWrite, Object: path("/x", false)}, false},
		{"abstract name with *", Rule{Ops: OpNet, Object: ObjectMatch{Unix: &UnixMatch{Abstract: true, Name: "a*"}}}, false},
		{"comm with for", Rule{Ops: OpAll, Object: ObjectMatch{Proc: &ProcMatch{Name: "environ", Comm: "x for 1h"}}}, false},
		{"comm with spaces around", Rule{Ops: OpAll, Object: ObjectMatch{Proc: &ProcMatch{Name: "environ", Comm: " x"}}}, false},
	} {
		if got := tc.r.Editable(now); got != tc.want {
			t.Errorf("%s: Editable() = %v, want %v (spec %q)", tc.name, got, tc.want, tc.r.EditSpec(now))
		}
	}
}
