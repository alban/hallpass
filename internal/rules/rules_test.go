// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"testing"
	"time"
)

func path(p string, tree bool, v Verdict, id uint64) Rule {
	return Rule{ID: id, Ops: OpAll, Object: ObjectMatch{Path: &PathMatch{Path: p, Tree: tree}}, Verdict: v}
}

func file(p string) Object { return Object{Path: &PathObject{Path: p}} }

func TestEval(t *testing.T) {
	now := time.Unix(1000, 0)
	rs := []Rule{
		path("/home/u/proj", true, Allow, 1),
		path("/home/u", true, Allow, 2),
		path("/home/u/.ssh", true, Ask, 3),
		path("/home/u/.ssh/known_hosts", false, Allow, 4),
		path("/home/u/proj/secret", true, Deny, 5),
		path("/home/u/.bashrc", false, Deny, 6),
		path("/home/u/old", true, Allow, 7),
	}
	rs[6].Expires = now
	for _, tc := range []struct {
		path string
		v    Verdict
		id   uint64
		ok   bool
	}{
		{"/home/u/proj/a.go", Allow, 1, true},
		{"/home/u/projX", Allow, 2, true},            // per component
		{"/home/u/.ssh/id", Ask, 3, true},            // Ask below an Allow cuts it off
		{"/home/u/.ssh/known_hosts", Allow, 4, true}, // Allow below an Ask re-allows
		{"/home/u/.ssh/known_hosts/x", Ask, 3, true}, // exact, not a tree
		{"/home/u/proj/secret/k", Deny, 5, true},     // Deny wins below an Allow
		{"/home/u/proj/secret/../a", Allow, 1, true}, // cleaned
		{"/home/u/.bashrc", Deny, 6, true},           // exact deny
		{"/home/u/old/x", Allow, 2, true},            // expired
		{"/etc/passwd", 0, 0, false},                 // no match
		{"/home/u/proj/secret", Deny, 5, true},       // the tree's root
		{"/home/u/.bashrc.d", Allow, 2, true},        // exact deny is exact
		{"/home/u/proj/secret/../secret/x", Deny, 5, true},
	} {
		v, id, ok := Eval(rs, OpWrite, file(tc.path), now)
		if v != tc.v || id != tc.id || ok != tc.ok {
			t.Errorf("Eval(%s) = %v, %d, %v; want %v, %d, %v", tc.path, v, id, ok, tc.v, tc.id, tc.ok)
		}
	}
}

func TestEvalDenyAbove(t *testing.T) {
	rs := []Rule{path("/a", true, Deny, 1), path("/a/b", true, Allow, 2)}
	if v, id, _ := Eval(rs, OpWrite, file("/a/b/c"), time.Time{}); v != Deny || id != 1 {
		t.Errorf("got %v %d, want a deny by 1", v, id)
	}
}

func TestEvalOps(t *testing.T) {
	r := path("/a", true, Allow, 1)
	r.Ops = OpWrite
	d := path("/a/x", false, Deny, 2)
	d.Ops = OpDelete
	rs := []Rule{r, d}
	for _, tc := range []struct {
		op   Op
		path string
		v    Verdict
		ok   bool
	}{
		{OpWrite, "/a/y", Allow, true},
		{OpWrite | OpCreate, "/a/y", 0, false}, // an allow must cover every op
		{OpDelete, "/a/y", 0, false},
		{OpDelete, "/a/x", Deny, true},
		{OpWrite, "/a/x", Allow, true},
		{OpDelete | OpWrite, "/a/x", Deny, true}, // a deny of any op denies
	} {
		if v, _, ok := Eval(rs, tc.op, file(tc.path), time.Time{}); v != tc.v || ok != tc.ok {
			t.Errorf("op %b on %s: %v %v, want %v %v", tc.op, tc.path, v, ok, tc.v, tc.ok)
		}
	}
	none := path("/", true, Allow, 3)
	none.Ops = 0
	if _, _, ok := Eval([]Rule{none}, OpWrite, file("/x"), time.Time{}); ok {
		t.Error("a rule with no op matched")
	}
}

func TestEvalProcAndUnknown(t *testing.T) {
	proc := Object{Proc: &ProcObject{Name: "oom_score_adj", Target: Subject{Chain: []Task{{Comm: "bash"}}}}}
	unknown := Object{Unknown: errors.New("EFAULT")}
	rs := []Rule{
		{ID: 1, Ops: OpAll, Object: ObjectMatch{Proc: &ProcMatch{Name: "oom_score_adj", Comm: "bash"}}},
		{ID: 2, Ops: OpAll, Object: ObjectMatch{Path: &PathMatch{Path: "/", Tree: true}}},
	}
	if v, id, ok := Eval(rs, OpWrite, proc, time.Time{}); !ok || v != Allow || id != 1 {
		t.Errorf("proc: %v %d %v", v, id, ok)
	}
	other := Object{Proc: &ProcObject{Name: "oom_score_adj", Target: Subject{Chain: []Task{{Comm: "sshd"}}}}}
	if _, _, ok := Eval(rs, OpWrite, other, time.Time{}); ok {
		t.Error("proc rule matched another comm")
	}
	// An unreadable path is matched by Unknown rules only, not by "/".
	if _, _, ok := Eval(rs, OpWrite, unknown, time.Time{}); ok {
		t.Error("a path rule matched an unknown path")
	}
	rs = append(rs, Rule{ID: 3, Ops: OpAll, Object: ObjectMatch{Unknown: true}, Verdict: Deny})
	if v, id, _ := Eval(rs, OpWrite, unknown, time.Time{}); v != Deny || id != 3 {
		t.Errorf("unknown: %v %d", v, id)
	}
}

func TestOpString(t *testing.T) {
	for op, want := range map[Op]string{
		OpWrite | OpCreate: "write", OpCreate: "create", OpMkdir: "create directory",
		OpSymlink: "create symlink", OpDelete: "delete", OpLink: "link", OpRename: "rename", OpTruncate: "truncate",
		OpConnect: "connect", OpSend: "send", OpExec: "exec",
	} {
		if got := op.String(); got != want {
			t.Errorf("%b: %q, want %q", op, got, want)
		}
	}
}

// TestEvalExec: exec rules decide execs only, and file rules do not decide
// execs. A rule with Args (not implemented yet) matches nothing.
func TestEvalExec(t *testing.T) {
	if OpAll&OpExec != 0 {
		t.Fatal("OpAll covers exec")
	}
	rs := []Rule{
		{ID: 1, Ops: OpAll, Verdict: Allow, Object: ObjectMatch{Path: &PathMatch{Path: "/", Tree: true}}},
		{ID: 2, Ops: OpExec, Verdict: Allow, Object: ObjectMatch{Path: &PathMatch{Path: "/usr/bin/ls"}}},
		{ID: 3, Ops: OpExec, Verdict: Deny, Object: ObjectMatch{Path: &PathMatch{Path: "/opt/bad", Tree: true}}},
		{ID: 4, Ops: OpExec, Verdict: Allow, Object: ObjectMatch{Path: &PathMatch{Path: "/usr/bin/git", Args: []string{"status"}}}},
	}
	for _, tc := range []struct {
		op   Op
		path string
		v    Verdict
		id   uint64
		ok   bool
	}{
		{OpExec, "/usr/bin/ls", Allow, 2, true},
		{OpExec, "/usr/bin/cat", 0, 0, false},
		{OpExec, "/opt/bad/x", Deny, 3, true},
		{OpExec, "/usr/bin/git", 0, 0, false},
		{OpWrite, "/opt/bad/x", Allow, 1, true},
	} {
		v, id, ok := Eval(rs, tc.op, file(tc.path), time.Time{})
		if v != tc.v || ok != tc.ok || (ok && id != tc.id) {
			t.Errorf("%v %s: %v %d %v, want %v %d %v", tc.op, tc.path, v, id, ok, tc.v, tc.id, tc.ok)
		}
	}
}
