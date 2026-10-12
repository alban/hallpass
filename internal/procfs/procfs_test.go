// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package procfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "secret")
	proj := filepath.Join(root, "proj")
	for _, d := range []string{filepath.Join(secret, "sub"), filepath.Join(proj, "dir")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"proj/abs":      secret,
		"proj/rel":      "../secret",
		"proj/subl":     secret + "/sub",
		"proj/relsub":   "dir/../../secret/sub", // dir is real: lexical == real here
		"proj/viasubl":  "subl/..",              // must resolve to secret, not proj
		"proj/dangling": secret + "/new",
		"proj/loop":     "loop",
	}
	for l, dst := range links {
		if err := os.Symlink(dst, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	pid := uint32(os.Getpid())

	for _, tc := range []struct {
		raw    string
		follow bool
		want   string
	}{
		{proj + "/dir/f", true, proj + "/dir/f"},
		{proj + "/abs/f", true, secret + "/f"},
		{proj + "/rel/f", true, secret + "/f"},
		{proj + "/subl/../f", true, secret + "/f"}, // ".." after a symlink
		{proj + "/viasubl/f", true, secret + "/f"},
		{proj + "/relsub/f", true, secret + "/sub/f"},
		{proj + "/dangling", true, secret + "/new"},
		{proj + "/dangling", false, proj + "/dangling"},
		{proj + "/abs", false, proj + "/abs"},
		{proj + "/./dir/../dir/f", true, proj + "/dir/f"},
		{proj + "/missing/../f", true, proj + "/f"},
	} {
		got, err := Resolve(pid, AtFDCWD, tc.raw, tc.follow)
		if err != nil {
			t.Errorf("Resolve(%s): %v", tc.raw, err)
			continue
		}
		if got.Path != tc.want {
			t.Errorf("Resolve(%s, follow=%v) = %s, want %s", tc.raw, tc.follow, got.Path, tc.want)
		}
	}

	if _, err := Resolve(pid, AtFDCWD, proj+"/loop/f", true); err == nil {
		t.Error("symlink loop: want error")
	}
}

func TestResolveRelative(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	got, err := Resolve(uint32(os.Getpid()), AtFDCWD, "a/../b", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != dir+"/b" {
		t.Errorf("got %s, want %s", got.Path, dir+"/b")
	}

	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err = Resolve(uint32(os.Getpid()), int64(f.Fd()), "c", true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != dir+"/c" {
		t.Errorf("dirfd: got %s, want %s", got.Path, dir+"/c")
	}
}

func TestResolveProcSelf(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	got, err := Resolve(uint32(os.Getpid()), AtFDCWD, "/proc/self/fd/"+strconv.Itoa(int(w.Fd())), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Special == "" {
		t.Errorf("pipe via /proc/self/fd: got %+v, want Special", got)
	}
}

func TestPidFile(t *testing.T) {
	for _, tc := range []struct {
		path string
		tid  int
		name string
		ok   bool
	}{
		{"/proc/12/oom_score_adj", 12, "oom_score_adj", true},
		{"/proc/12/task/13/comm", 13, "comm", true},
		{"/proc/12/attr/current", 12, "current", true},
		{"/proc/12", 0, "", false},
		{"/proc/sys/vm/swappiness", 0, "", false},
		{"/proc/0/x", 0, "", false},
		{"/home/u/proc/12/x", 0, "", false},
	} {
		tid, name, ok := PidFile(tc.path)
		if tid != tc.tid || name != tc.name || ok != tc.ok {
			t.Errorf("PidFile(%q) = %d, %q, %v; want %d, %q, %v", tc.path, tid, name, ok, tc.tid, tc.name, tc.ok)
		}
	}
}

func TestDescends(t *testing.T) {
	if !Descends(os.Getpid(), os.Getpid()) {
		t.Error("a process descends from itself")
	}
	if !Descends(os.Getpid(), os.Getppid()) {
		t.Error("a process descends from its parent")
	}
	if Descends(os.Getppid(), os.Getpid()) {
		t.Error("the parent descends from its child")
	}
}

func TestCmdlineAncestors(t *testing.T) {
	child := exec.Command("sleep", "60")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	pid := child.Process.Pid

	// Until the exec completes, the child's cmdline is the test binary's,
	// then briefly empty.
	got := Cmdline(pid)
	for i := 0; i < 100 && !slices.Equal(got, []string{"sleep", "60"}); i++ {
		time.Sleep(10 * time.Millisecond)
		got = Cmdline(pid)
	}
	if !slices.Equal(got, []string{"sleep", "60"}) {
		t.Errorf("Cmdline = %q", got)
	}
	if got, want := Ancestors(pid, os.Getpid(), 4), []string{Comm(os.Getpid())}; !slices.Equal(got, want) {
		t.Errorf("Ancestors(child, self) = %q, want %q", got, want)
	}
	if got := Ancestors(os.Getpid(), os.Getpid(), 4); got != nil {
		t.Errorf("Ancestors(self, self) = %q, want none", got)
	}
	if got := Ancestors(pid, os.Getpid(), 0); got != nil {
		t.Errorf("Ancestors with max 0 = %q", got)
	}
}
