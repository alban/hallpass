// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// copyTrue copies the true program to path.
func copyTrue(t *testing.T, path string) {
	t.Helper()
	src, err := exec.LookPath("true")
	if err != nil {
		t.Skip(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestExec checks the exec rules: the programs a member may run, and the
// #! interpreters of scripts, and that file rules do not allow execs.
func TestExec(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir+"/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"ok", "other", "sub/a", "sub/denied"} {
		copyTrue(t, filepath.Join(dir, n))
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	if sh, err = filepath.EvalSymlinks(sh); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/script", []byte("#!"+sh+"\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	off, on := newSession(t, l), newSession(t, l)
	go on.Events(func(e Event) { t.Logf("event: %+v", e) })
	if err := off.Mediate(true, false, false); err != nil {
		t.Fatal(err)
	}
	if err := on.Mediate(true, true, false); err != nil {
		t.Fatal(err)
	}
	rs := []Rule{
		devNull,
		{Path: dir, Tree: true}, // files only
		{Path: dir + "/ok", Exec: true},
		{Path: dir + "/sub", Tree: true, Exec: true},
		{Path: dir + "/sub/denied", Exec: true, Deny: true},
		{Path: dir + "/script", Exec: true},
	}
	for _, s := range []*Session{off, on} {
		if err := s.Sync(rs, nil); err != nil {
			t.Fatal(err)
		}
	}
	script := try + fmt.Sprintf(`for p in ok other sub/a sub/denied script; do printf "%%s=" $p; try %s/$p; done`, dir)
	_, runOff := member(t, off, script)
	_, runOn := member(t, on, script)
	if got, want := strings.Fields(runOff()), "ok=ok other=ok sub/a=ok sub/denied=ok script=ok"; strings.Join(got, " ") != want {
		t.Errorf("exec not mediated: %s, want %s", got, want)
	}
	// The script's interpreter is not allowed.
	if got, want := strings.Fields(runOn()), "ok=ok other=fail sub/a=ok sub/denied=fail script=fail"; strings.Join(got, " ") != want {
		t.Errorf("exec mediated: %s, want %s", got, want)
	}

	if err := on.Sync(append(rs, Rule{Path: sh, Exec: true}), nil); err != nil {
		t.Fatal(err)
	}
	_, run := member(t, on, try+fmt.Sprintf("try %s/script", dir))
	if got := run(); got != "ok" {
		t.Errorf("script with its interpreter allowed: %s, want ok", got)
	}
}
