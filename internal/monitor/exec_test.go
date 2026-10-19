// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

func execRule(path string, v rules.Verdict) rules.Rule {
	return rules.Rule{Ops: rules.OpExec, Verdict: v, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: path}}}
}

func (f *fakeNotifier) execve(path string) uint64 {
	return f.send(unix.SYS_EXECVE, map[int]string{0: path}, nil)
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestExec(t *testing.T) {
	fx := setupConfig(t, Config{}, false)
	ok, no, other := filepath.Join(fx.dir, "ok"), filepath.Join(fx.dir, "no"), filepath.Join(fx.dir, "other")
	for _, p := range []string{ok, no, other} {
		writeExec(t, p, "\x7fELF")
	}
	if err := os.Symlink(ok, filepath.Join(fx.dir, "link")); err != nil {
		t.Fatal(err)
	}
	// A file rule on the folder does not decide execs.
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{execRule(ok, rules.Allow), execRule(no, rules.Deny), tree(fx.dir, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, fx.f.execve(ok), 0)
	fx.f.expect(t, fx.f.execve(filepath.Join(fx.dir, "link")), 0) // resolved
	fx.f.expect(t, fx.f.execve(no), int32(unix.EACCES))
	// Not an executable file: the kernel fails the exec.
	fx.f.expect(t, fx.f.execve(filepath.Join(fx.dir, "missing")), 0)

	id := fx.f.execve(other)
	req := fx.next(t, opened).Opened
	if req.Op != rules.OpExec || req.Objects[0].Path.Path != other || req.Syscall != "execve" {
		t.Fatalf("request %+v", req)
	}
	fx.f.expectNone(t)
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EACCES))

	// execvp tries the next $PATH directory: the same program, through a
	// symlink, is not asked about again.
	if err := os.Symlink(other, filepath.Join(fx.dir, "other-link")); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, fx.f.execve(filepath.Join(fx.dir, "other-link")), int32(unix.EACCES))
}

// TestExecScript: a script runs only if its #! interpreters may run too.
func TestExecScript(t *testing.T) {
	fx := setupConfig(t, Config{}, false)
	interp, script := filepath.Join(fx.dir, "interp"), filepath.Join(fx.dir, "script")
	writeExec(t, interp, "\x7fELF")
	writeExec(t, script, "#! "+interp+" -x\necho\n")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{execRule(script, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	// The script is allowed: the interpreter is asked about.
	id := fx.f.execve(script)
	req := fx.next(t, opened).Opened
	if req.Objects[0].Path.Path != interp {
		t.Fatalf("request objects %+v", req.Objects[0].Path)
	}
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, int32(unix.EACCES))

	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{execRule(interp, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, fx.f.execve(script), 0)
}

// TestExecNotMediated: without exec in Config.Mediate, execs are continued.
func TestExecNotMediated(t *testing.T) {
	fx := setupConfig(t, Config{Mediate: seccomp.Files}, false)
	p := filepath.Join(fx.dir, "p")
	writeExec(t, p, "\x7fELF")
	fx.f.expect(t, fx.f.execve(p), 0)
}

// TestExecStrict: in strict mode, an allowed exec is left to the kernel,
// which has the rule; an answered one is granted once.
func TestExecStrict(t *testing.T) {
	k := &fakeKernel{}
	fx := setupConfig(t, Config{Kernel: k}, false)
	ok, other := filepath.Join(fx.dir, "ok"), filepath.Join(fx.dir, "other")
	writeExec(t, ok, "\x7fELF")
	writeExec(t, other, "\x7fELF")
	if _, err := fx.m.Apply(Decision{AddRules: []rules.Rule{execRule(ok, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	k.mu.Lock()
	var found bool
	for _, r := range k.paths {
		if r == (lsm.Rule{Path: ok, Exec: true}) {
			found = true
		}
	}
	k.mu.Unlock()
	if !found {
		t.Fatalf("kernel rules %+v lack the exec rule", k.paths)
	}
	fx.f.expect(t, fx.f.execve(ok), 0)
	id := fx.f.execve(other)
	req := fx.next(t, opened).Opened
	if _, err := fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}, Client: "test"}); err != nil {
		t.Fatal(err)
	}
	fx.f.expect(t, id, 0)
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.members) != 2 || len(k.grants) != 1 || len(k.grants[0]) != 1 || k.grants[0][0] != other {
		t.Errorf("members %v grants %v", k.members, k.grants)
	}
}
