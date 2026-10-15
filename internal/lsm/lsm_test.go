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
	"time"

	"golang.org/x/sys/unix"
)

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		skip(t, "needs root (go test -exec sudo)")
	}
}

// skip skips the test, or fails it under HALLPASS_REQUIRE_LSM=1, which CI
// sets on the kernels where strict mode must work, so that a test that
// cannot run does not pass silently.
func skip(t *testing.T, args ...any) {
	t.Helper()
	if os.Getenv("HALLPASS_REQUIRE_LSM") == "1" {
		t.Fatal(append([]any{"HALLPASS_REQUIRE_LSM=1:"}, args...)...)
	}
	t.Skip(args...)
}

// TestLoad runs the verifier and attaches, which works even where BPF-LSM is
// built but not active.
func TestLoad(t *testing.T) {
	needRoot(t)
	if err := Supported(); err != nil {
		skip(t, err)
	}
	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Sync([]Rule{{Path: "/tmp", Tree: true}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestFromFDs(t *testing.T) {
	needRoot(t)
	if err := Supported(); err != nil {
		skip(t, err)
	}
	l, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dup := func(swap int) []int {
		var fds []int
		for _, fd := range l.FDs() {
			d, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			fds = append(fds, d)
		}
		if swap > 0 {
			fds[swap], fds[swap+1] = fds[swap+1], fds[swap]
		}
		return fds
	}
	l2, err := FromFDs(dup(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Sync([]Rule{{Path: "/tmp", Tree: true}}, nil); err != nil {
		t.Error(err)
	}
	l2.Close()
	for _, swap := range []int{5, 7, len(l.FDs()) - 2} { // a map as a link; two links swapped; sys_exit as LSM
		if l3, err := FromFDs(dup(swap)); err == nil {
			l3.Close()
			t.Errorf("swap at %d accepted", swap)
		} else {
			t.Logf("swap at %d: %v", swap, err)
		}
	}
	if _, err := FromFDs(dup(0)[:7]); err == nil {
		t.Error("missing links accepted")
	}
	if _, err := FromFDs(dup(0)[:len(l.FDs())-1]); err == nil {
		t.Error("missing sys_exit link accepted")
	}
}

// TestGrantOnce checks that a grant only lasts until the syscall the thread
// is in returns: here a read, so the write after it is denied.
func TestGrantOnce(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	dir := t.TempDir()
	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Sync(nil, nil); err != nil {
		t.Fatal(err)
	}
	go l.Events(func(e Event) { t.Logf("event: %+v", e) })

	sh := exec.Command("sh", "-c", `read go; if echo > "$0/f"; then echo ok; else echo fail; fi`, dir)
	stdin, _ := sh.StdinPipe()
	var out strings.Builder
	sh.Stdout = &out
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	if err := l.AddMember(sh.Process.Pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // blocked in read
	if err := l.GrantOnce(sh.Process.Pid, []string{dir + "/f"}, ProcRule{}); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	if len(l.once) != 1 {
		t.Errorf("%d grants pending, want 1", len(l.once))
	}
	l.mu.Unlock()
	stdin.Write([]byte("go\n"))
	stdin.Close()
	if err := sh.Wait(); err != nil {
		t.Fatalf("sh: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "fail" {
		t.Errorf("write after the granted syscall: %s, want fail", got)
	}
	if err := l.Sync(nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(l.once) != 0 || len(l.nodes) != 0 {
		t.Errorf("used grant not forgotten: %d grants, %d nodes", len(l.once), len(l.nodes))
	}
}

// TestEnforce runs a shell as a member and checks what it may write.
func TestEnforce(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	base := t.TempDir()
	allowed, other := filepath.Join(base, "allowed"), filepath.Join(base, "other")
	nested := filepath.Join(base, "nested")
	for _, d := range []string{allowed + "/secret", allowed + "/bind", allowed + "/nested", nested, other + "/mnt", other + "/existing"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(other+"/plain", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowed+"/secret/victim", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Mounted before Sync, below an allowed folder: covered by its rule.
	if err := unix.Mount(nested, allowed+"/nested", "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(allowed+"/nested", unix.MNT_DETACH)

	outsider := exec.Command("sleep", "60")
	if err := outsider.Start(); err != nil {
		t.Fatal(err)
	}
	defer outsider.Process.Kill()

	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Sync([]Rule{
		{Path: allowed, Tree: true},
		{Path: allowed + "/secret", Tree: true, Deny: true},
		{Path: other + "/once", Expires: time.Now().Add(5 * time.Second)},
		{Path: "/dev/null", Tree: true},
	}, nil); err != nil {
		t.Fatal(err)
	}
	go l.Events(func(e Event) { t.Logf("event: %+v", e) })

	cases := []struct {
		name, cmd string
		ok        bool
	}{
		{"allowed", "echo > A/f", true},
		{"mkdir allowed", "mkdir A/d", true},
		{"other", "echo > O/f", false},
		{"secret", "echo > A/secret/f", false},
		{"exact rule", "echo > O/once", true},
		{"exact rule is not a tree", "mkdir O/once.d 2>/dev/null; echo > O/once/x", false},
		{"nested mount", "echo > N/f", true},
		{"own bind mount of other", "unshare -m sh -c 'mount --bind O A/bind && echo > A/bind/f'", false},
		{"rename out", "mv A/f O/f", false},
		{"rename in", "mv O/existing A/stolen", false},
		{"hard link", "ln O/plain A/link", false},
		{"symlink then write through it", "ln -s ../other/g A/sym && echo > A/sym", false},
		{"devnull", "echo > /dev/null", true},
		// Not comm: only its own thread group may write it.
		{"member proc", "echo 0 > /proc/$$/oom_score_adj", true},
		{"outsider proc", fmt.Sprintf("echo 0 > /proc/%d/oom_score_adj", outsider.Process.Pid), false},
		{"own tmpfs", "unshare -m sh -c 'mount -t tmpfs none O/mnt && echo > O/mnt/f'", true},
		// Overlayfs writes to its layers with internal vfs_* calls, which
		// skip the path hooks, so members may not mount it.
		{"overlay mount", "unshare -Urm sh -c 'mkdir -p A/ov2/low A/ov2/up A/ov2/work A/ov2/merged && mount -t overlay overlay -o lowerdir=A/ov2/low,upperdir=A/ov2/up,workdir=A/ov2/work A/ov2/merged'", false},
		{"unlink via overlay upper", "unshare -Urm sh -c 'mkdir -p A/ov3/low A/ov3/work A/ov3/merged && mount -t overlay overlay -o lowerdir=A/ov3/low,upperdir=A/secret,workdir=A/ov3/work A/ov3/merged && rm A/ov3/merged/victim'", false},
		{"copy-up into overlay upper", "unshare -Urm sh -c 'mkdir -p A/ov4/low A/ov4/work A/ov4/merged && echo planted > A/ov4/low/planted && mount -t overlay overlay -o lowerdir=A/ov4/low,upperdir=A/secret,workdir=A/ov4/work A/ov4/merged && touch A/ov4/merged/planted'", false},
		{"read", "cat O/once >/dev/null", true},
	}
	var script strings.Builder
	script.WriteString("read go\n")
	for i, c := range cases {
		fmt.Fprintf(&script, "if (%s) 2>/dev/null; then echo %d ok; else echo %d fail; fi\n", c.cmd, i, i)
	}
	sh := exec.Command("sh", "-c", strings.NewReplacer("A/", allowed+"/", "O/", other+"/", "N/", nested+"/", " O ", " "+other+" ").Replace(script.String()))
	stdin, _ := sh.StdinPipe()
	var out strings.Builder
	sh.Stdout = &out
	sh.Stderr = os.Stderr
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	if err := l.AddMember(sh.Process.Pid); err != nil {
		t.Fatal(err)
	}
	stdin.Write([]byte("go\n"))
	stdin.Close()
	if err := sh.Wait(); err != nil {
		t.Fatalf("sh: %v\n%s", err, out.String())
	}
	got := strings.Fields(out.String())
	for i, c := range cases {
		want := "fail"
		if c.ok {
			want = "ok"
		}
		if 2*i+1 >= len(got) || got[2*i+1] != want {
			t.Errorf("%s (%s): want %s\n%s", c.name, c.cmd, want, out.String())
		}
	}
	if _, err := os.Stat(allowed + "/secret/victim"); err != nil {
		t.Errorf("victim: %v", err)
	}
	if _, err := os.Stat(allowed + "/secret/planted"); err == nil {
		t.Error("planted file in the denied dir")
	}
	time.Sleep(100 * time.Millisecond) // let the events be logged
}
