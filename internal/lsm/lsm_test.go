// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
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

// newSession starts a session of l, closed with the test.
func newSession(t *testing.T, l *LSM) *Session {
	t.Helper()
	s, err := l.NewSession(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
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
	if err := newSession(t, l).Sync([]Rule{{Path: "/tmp", Tree: true}}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestReadOwnSecurityfs reads the LSM list as a container does where
// securityfs is not mounted.
func TestReadOwnSecurityfs(t *testing.T) {
	needRoot(t)
	want, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Skip(err)
	}
	got, err := readOwnSecurityfs()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("got %q, want %q", got, want)
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
	if err := newSession(t, l2).Sync([]Rule{{Path: "/tmp", Tree: true}}, nil); err != nil {
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
	s := newSession(t, l)
	if err := s.Sync(nil, nil); err != nil {
		t.Fatal(err)
	}
	go s.Events(func(e Event) { t.Logf("event: %+v", e) })

	sh := exec.Command("sh", "-c", `read go; if echo > "$0/f"; then echo ok; else echo fail; fi`, dir)
	stdin, _ := sh.StdinPipe()
	var out strings.Builder
	sh.Stdout = &out
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(sh.Process.Pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // blocked in read
	if err := s.GrantOnce(sh.Process.Pid, []string{dir + "/f"}, ProcRule{}); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if len(s.once) != 1 {
		t.Errorf("%d grants pending, want 1", len(s.once))
	}
	s.mu.Unlock()
	stdin.Write([]byte("go\n"))
	stdin.Close()
	if err := sh.Wait(); err != nil {
		t.Fatalf("sh: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "fail" {
		t.Errorf("write after the granted syscall: %s, want fail", got)
	}
	if err := s.Sync(nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.once) != 0 || len(s.nodes) != 0 {
		t.Errorf("used grant not forgotten: %d grants, %d nodes", len(s.once), len(s.nodes))
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
	s := newSession(t, l)
	if err := s.Sync([]Rule{
		{Path: allowed, Tree: true},
		{Path: allowed + "/secret", Tree: true, Deny: true},
		{Path: other + "/once", Expires: time.Now().Add(5 * time.Second)},
		{Path: "/dev/null", Tree: true},
	}, nil); err != nil {
		t.Fatal(err)
	}
	go s.Events(func(e Event) { t.Logf("event: %+v", e) })

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
	if err := s.AddMember(sh.Process.Pid); err != nil {
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

// member starts sh -c script as a member of s. It runs once go is closed,
// and its output is returned by the func returned.
func member(t *testing.T, s *Session, script string) (pid int, run func() string) {
	t.Helper()
	sh := exec.Command("sh", "-c", "read go\n"+script)
	stdin, _ := sh.StdinPipe()
	var out strings.Builder
	sh.Stdout = &out
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(sh.Process.Pid); err != nil {
		sh.Process.Kill()
		t.Fatal(err)
	}
	return sh.Process.Pid, func() string {
		stdin.Write([]byte("go\n"))
		stdin.Close()
		if err := sh.Wait(); err != nil {
			t.Fatalf("sh: %v\n%s", err, out.String())
		}
		return strings.TrimSpace(out.String())
	}
}

const try = `try() { if (eval "$1") 2>/dev/null; then echo ok; else echo fail; fi; }
`

// devNull lets the try scripts discard their errors.
var devNull = Rule{Path: "/dev/null", Tree: true}

// TestSessions checks that the members of two sessions get the rules of
// their own session, may only write the /proc files of their own session,
// and that each session gets its own events.
func TestSessions(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	a, b := t.TempDir(), t.TempDir()
	l, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	sa, sb := newSession(t, l), newSession(t, l)
	if sa.ID() == sb.ID() {
		t.Fatalf("same session id %d", sa.ID())
	}
	if err := sa.Sync([]Rule{{Path: a, Tree: true}, devNull}, nil); err != nil {
		t.Fatal(err)
	}
	if err := sb.Sync([]Rule{{Path: b, Tree: true}, devNull}, nil); err != nil {
		t.Fatal(err)
	}
	events := map[*Session][]Event{}
	var mu sync.Mutex
	for _, s := range []*Session{sa, sb} {
		go s.Events(func(e Event) {
			if !strings.HasPrefix(e.Path, a) && !strings.HasPrefix(e.Path, b) && !strings.HasPrefix(e.Path, "/proc/") {
				return // sh probing /dev/tty
			}
			mu.Lock()
			events[s] = append(events[s], e)
			mu.Unlock()
		})
	}

	pb, runB := member(t, sb, try+fmt.Sprintf(`try "echo > %s/f"; try "echo > %s/f"; try "echo 0 > /proc/$$/oom_score_adj"`, b, a))
	_, runA := member(t, sa, try+fmt.Sprintf(`try "echo > %s/f"; try "echo > %s/f"; try "echo 0 > /proc/%d/oom_score_adj"`, a, b, pb))
	if got := strings.Join(strings.Fields(runA()), " "); got != "ok fail fail" {
		t.Errorf("session A: own dir, other dir, other session's proc: %s, want ok fail fail", got)
	}
	if got := strings.Join(strings.Fields(runB()), " "); got != "ok fail ok" {
		t.Errorf("session B: own dir, other dir, own proc: %s, want ok fail ok", got)
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(events[sa]) != 2 || len(events[sb]) != 1 {
		t.Errorf("events: A %v, B %v; want 2 denials for A, 1 for B", events[sa], events[sb])
	}
}

// TestResume checks that a new owner of the programs (FromFDs) can take
// over a session and its members, and drop the rules of the others.
func TestResume(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	a, b := t.TempDir(), t.TempDir()
	l, err := Load(false)
	if err != nil {
		t.Fatal(err)
	}
	s := newSession(t, l)
	if err := s.Sync([]Rule{{Path: a, Tree: true}, devNull}, nil); err != nil {
		t.Fatal(err)
	}
	gone := newSession(t, l)
	if err := gone.Sync([]Rule{{Path: b, Tree: true}}, []ProcRule{{Name: "comm", Comm: "x"}}); err != nil {
		t.Fatal(err)
	}
	script := try + fmt.Sprintf(`try "echo > %s/f"; try "echo > %s/f"`, a, b)
	_, before := member(t, s, script)
	_, after := member(t, s, script)
	var fds []int
	for _, fd := range l.FDs() {
		d, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, d)
	}
	l2, err := FromFDs(fds)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	l.Close() // the programs stay attached by l2's links
	s2, err := l2.ResumeSession(s.ID(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if n, err := l2.NewSession(0); err != nil || n.ID() <= gone.ID() {
		t.Errorf("new session after resume: %v, %v", n, err)
	} else {
		n.Close()
	}
	l2.DropStale()
	count := func(m *ebpf.Map) (n int) {
		var k, v []byte
		it := m.Iterate()
		for it.Next(&k, &v) {
			n++
		}
		return n
	}
	if n := count(l2.rules); n != len(s2.nodes) {
		t.Errorf("%d rules after DropStale, want the resumed session's %d", n, len(s2.nodes))
	}
	if n := count(l2.proc); n != 0 {
		t.Errorf("%d proc rules after DropStale, want 0", n)
	}
	// The old owner's rules are still in force for the resumed session.
	if got := strings.Join(strings.Fields(before()), " "); got != "ok fail" {
		t.Errorf("resumed, not synced: %s, want ok fail", got)
	}
	// The new owner's rules: a cookie reused from the old ones would match
	// the wrong node.
	if err := s2.Sync([]Rule{{Path: b, Tree: true}, devNull}, nil); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(strings.Fields(after()), " "); got != "fail ok" {
		t.Errorf("resynced to b: %s, want fail ok", got)
	}
}
