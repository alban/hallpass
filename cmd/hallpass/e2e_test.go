// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/sessionapi"
)

var hallpassBin string

func TestMain(m *testing.M) {
	if mode := os.Getenv("HALLPASS_E2E_HELPER"); mode != "" {
		os.Exit(goHelper(mode))
	}
	// HALLPASS_BIN is a binary built beforehand, e.g. on the host by
	// `make test-vm`, so that the VM does not have to run the linker.
	if bin := os.Getenv("HALLPASS_BIN"); bin != "" {
		hallpassBin = bin
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "hallpass-bin")
	if err != nil {
		panic(err)
	}
	hallpassBin = filepath.Join(dir, "hallpass")
	if out, err := exec.Command("go", "build", "-o", hallpassBin, ".").CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build: %v\n%s", err, out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	root, home, proj, runtime string
}

// newEnv creates a fake $HOME outside /tmp, like a real one.
func newEnv(t *testing.T) env {
	t.Helper()
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no cache dir")
	}
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(cache, "hallpass-e2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	root, _ = filepath.EvalSymlinks(root)
	e := env{root: root, home: root + "/home", proj: root + "/home/proj", runtime: root + "/run"}
	for _, d := range []string{e.proj, e.home + "/.ssh/sub", e.runtime} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(e.home+"/.ssh/id", []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e env) cmd(script string, flags ...string) *exec.Cmd {
	args := append(append([]string{}, flags...), "-C", e.proj, "--", "/bin/sh", "-c", script)
	c := exec.Command(hallpassBin, args...)
	c.Env = append(os.Environ(), "HOME="+e.home, "XDG_RUNTIME_DIR="+e.runtime, "DBUS_SESSION_BUS_ADDRESS=")
	return c
}

func TestDenyMode(t *testing.T) {
	e := newEnv(t)
	script := `
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=allowed"; else echo "$name=denied"; fi; }
check workdir  sh -c 'echo x > inside'
check home     sh -c 'echo x > "$HOME/outside"'
check ssh      sh -c 'echo x >> "$HOME/.ssh/id"'
check sshnew   sh -c 'echo x > "$HOME/.ssh/new"'
check rmssh    rm -f "$HOME/.ssh/id"
check mkdir    mkdir "$HOME/d"
ln -s "$HOME/.ssh" lnk
check symlink  sh -c 'echo x > lnk/new'
ln -s "$HOME/.ssh/sub" lnksub
check dotdot   sh -c 'echo x > lnksub/../authorized_keys'
check hardlink ln "$HOME/.ssh/id" stolen
check mvout    sh -c 'echo x > m && mv m "$HOME/m"'
check mvin     mv "$HOME/.ssh/id" ./id
check userns   unshare -U true
check tmp      sh -c 'echo x > /tmp/hallpass-e2e-$$ && rm /tmp/hallpass-e2e-$$'
check shm      sh -c 'echo x > /dev/shm/hallpass-e2e-$$ && rm /dev/shm/hallpass-e2e-$$'
check tmpdir   sh -c 'echo x > "$TMPDIR/f" && rm "$TMPDIR/f"'
check mktemp   sh -c 'rm "$(mktemp)"'
echo "TMPDIR=$TMPDIR"
exit 7
`
	c := e.cmd(script, "--ask=deny")
	out, err := c.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 7 {
		t.Fatalf("exit: %v (want 7)\n%s", err, out)
	}
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	want := map[string]string{
		"workdir": "allowed", "home": "denied", "ssh": "denied", "sshnew": "denied",
		"rmssh": "denied", "mkdir": "denied", "symlink": "denied", "dotdot": "denied",
		"hardlink": "denied", "mvout": "denied", "mvin": "denied", "userns": "denied",
		"tmp": "denied", "shm": "denied", "tmpdir": "allowed", "mktemp": "allowed",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if d := got["TMPDIR"]; !strings.Contains(d, "/hallpass-") {
		t.Errorf("TMPDIR = %q, want a per-session hallpass-* dir", d)
	} else if _, err := os.Lstat(d); err == nil {
		t.Errorf("empty TMPDIR %s not removed at exit", d)
	}
	if b, _ := os.ReadFile(e.home + "/.ssh/id"); string(b) != "secret\n" {
		t.Errorf("~/.ssh/id modified: %q", b)
	}
	for _, p := range []string{"/outside", "/.ssh/new", "/.ssh/authorized_keys", "/d", "/m"} {
		if _, err := os.Lstat(e.home + p); err == nil {
			t.Errorf("%s was created", p)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

// TestOrphan checks that a process whose parent exited is still mediated:
// under Yama's ptrace_scope=1, reading its syscall arguments needs hallpass
// to stay its ancestor, as subreaper.
func TestOrphan(t *testing.T) {
	e := newEnv(t)
	script := `(sh -c 'sleep 0.3; echo x > inside' &); sleep 1; test -f inside && echo orphan=allowed`
	out, err := e.cmd(script, "--ask=deny").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "orphan=allowed") {
		t.Errorf("orphan write in the project: %v\n%s", err, out)
	}
}

func TestAnswerSocket(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.home+"/.m2/r", 0o700); err != nil {
		t.Fatal(err)
	}
	script := `
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
check a    sh -c 'echo a > "$HOME/.m2/a"'
check a2   sh -c 'echo a2 > "$HOME/.m2/r/a2"'
v=$(cat /proc/self/oom_score_adj)
check self sh -c "echo $v > /proc/self/oom_score_adj"
check b1   sh -c 'echo b > "$HOME/b"'
check b2   sh -c 'echo b > "$HOME/b"'
check b3   sh -c 'echo b > "$HOME/b"'
v=$(cat /proc/$PPID/oom_score_adj)
check out1 sh -c "echo $v > /proc/$PPID/oom_score_adj"
check out2 sh -c "echo $v > /proc/$PPID/oom_score_adj"
`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	// "temp" on ~/.m2/a grants ~/.m2 for 5 minutes, so a2 goes through
	// without prompting. Writes to the sandbox's own /proc files are
	// silent. "deny" is not remembered (b2 asks again), "never" is (b3
	// does not). A write to hallpass's own /proc files is outside the
	// sandbox: asked, and "always" covers the retry.
	steps := []struct{ suffix, scope, reply string }{
		{"/.m2/a", "/.m2", "temp"},
		{"/b", "", "deny"},
		{"/b", "", "never"},
		{"/oom_score_adj", `oom_score_adj of "hallpass" processes outside the sandbox`, "always"},
	}
	for _, st := range steps {
		req, err := p.nextRequest(10 * time.Second)
		if err != nil {
			t.Fatalf("read prompt: %v\n%s", err, out.String())
		}
		if path, scope := req.Prompt.GetPath(), req.Prompt.GetScope(); !strings.HasSuffix(path, st.suffix) || !strings.HasSuffix(scope, st.scope) {
			t.Errorf("prompt for %q (scope %q), want *%s (scope *%s)", path, scope, st.suffix, st.scope)
		}
		// A stale answer must be refused.
		_, err = p.c.Answer(context.Background(), &pb.AnswerRequest{Request: req.Id + 1000, Answer: "once"})
		if status.Code(err) != codes.NotFound {
			t.Errorf("stale answer: %v, want NotFound", err)
		}
		p.answer(req.Id, st.reply)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	for _, want := range []string{"a=ok", "a2=ok", "self=ok", "b1=denied", "b2=denied", "b3=denied", "out1=ok", "out2=ok"} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("output lacks %q", want)
		}
	}
	if _, err := os.Stat(e.home + "/b"); err == nil {
		t.Error("b was created despite deny")
	}
	if t.Failed() {
		t.Logf("output:\n%s", out.String())
	}
}

// TestUnknownPath checks that a write whose path hallpass cannot read is
// asked about, flagged, with only "once", "deny" and "never" offered.
func TestUnknownPath(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("needs python3")
	}
	e := newEnv(t)
	// openat with an unmapped path pointer: the kernel fails it with
	// EFAULT once hallpass lets it through.
	script := `python3 -c '
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
for i in range(3):
    libc.openat(-100, ctypes.c_void_p(1), 0o101, 0o644)
    print("errno=%d" % ctypes.get_errno(), flush=True)
'`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	for _, reply := range []string{"once", "never"} {
		req, err := p.nextRequest(10 * time.Second)
		if err != nil {
			t.Fatalf("read prompt: %v\n%s", err, out.String())
		}
		if pr := req.Prompt; pr.GetScope() != "" || !strings.HasPrefix(pr.GetWarn(), "Unknown path") {
			t.Errorf("prompt %v: want no scope and an unknown-path warning", pr)
		}
		p.answer(req.Id, reply)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	// once: EFAULT from the kernel; never: EACCES, then EACCES unasked.
	if want := "errno=14\nerrno=13\nerrno=13\n"; !strings.HasSuffix(out.String(), want) {
		t.Errorf("output %q, want %q", out.String(), want)
	}
}

type logLine struct {
	Path, Decision, Reason string
}

// TestAnswerCommand runs `hallpass answer` against a session.
func TestAnswerCommand(t *testing.T) {
	e := newEnv(t)
	script := `
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
check a sh -c 'echo a > "$HOME/a"'
check b sh -c 'echo b > "$HOME/b"'
`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	dialPrompts(t, e, c) // waits for the socket
	a := exec.Command(hallpassBin, "answer")
	a.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+e.runtime)
	in, err := a.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	scr := &screen{emu: vt.NewEmulator(100, 24)}
	a.Stdout, a.Stderr = scr, scr
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"o", "d"} {
		waitFor(t, func() bool { return strings.Count(scr.rawText(), "wants to write") > i }, "prompt")
		fmt.Fprintln(in, key)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	if err := a.Wait(); err != nil {
		t.Errorf("hallpass answer: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "a=ok\n") || !strings.Contains(got, "b=denied\n") {
		t.Errorf("output:\n%s", got)
	}
	if got := scr.rawText(); !strings.HasSuffix(got, "Session ended.\n") {
		t.Errorf("hallpass answer output:\n%s", got)
	}
}

// prompter answers the prompts of a hallpass run with --ask=answer, over
// the session's gRPC socket.
type prompter struct {
	t *testing.T
	c pb.SessionClient
}

func dialPrompts(t *testing.T, e env, c *exec.Cmd) prompter {
	t.Helper()
	sock := fmt.Sprintf("%s/hallpass/%d.sock", e.runtime, c.Process.Pid)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			conn, client, err := sessionapi.Dial(sock)
			if err != nil {
				break
			}
			t.Cleanup(func() { conn.Close() })
			return prompter{t, client}
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.Process.Kill()
	t.Fatalf("dial %s", sock)
	return prompter{}
}

// nextRequest returns the oldest pending request, waiting at most d. It
// polls Snapshot, which reflects answers as soon as Answer returns, so a
// request settled by the previous answer is never returned.
func (p prompter) nextRequest(d time.Duration) (*pb.Request, error) {
	deadline := time.Now().Add(d)
	for {
		s, err := p.c.Snapshot(context.Background(), &pb.SnapshotRequest{})
		if err != nil {
			return nil, err
		}
		if len(s.Pending) > 0 {
			oldest := s.Pending[0]
			for _, r := range s.Pending {
				if r.Id < oldest.Id {
					oldest = r
				}
			}
			return oldest, nil
		}
		if time.Now().After(deadline) {
			return nil, errors.New("no prompt")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// next returns the ID and path of the next prompt, waiting at most d.
func (p prompter) next(d time.Duration) (uint64, string, error) {
	r, err := p.nextRequest(d)
	if err != nil {
		return 0, "", err
	}
	return r.Id, r.Prompt.GetPath(), nil
}

// answer answers request id, failing the test on error.
func (p prompter) answer(id uint64, reply string) {
	p.t.Helper()
	if _, err := p.c.Answer(context.Background(), &pb.AnswerRequest{Request: id, Answer: reply, Client: "test"}); err != nil {
		p.t.Errorf("answer %d %s: %v", id, reply, err)
	}
}

// TestSignalWhilePrompting checks that a signal caught by the sandboxed
// process while it waits for an answer does not abort and restart the
// syscall, which would ask again (SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV).
func TestSignalWhilePrompting(t *testing.T) {
	e := newEnv(t)
	script := `trap 'echo sig' USR1; (sleep 0.3; kill -USR1 $$) & if echo x > "$HOME/sig"; then echo write=ok; else echo write=failed; fi; wait`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	id, path, err := p.next(10 * time.Second)
	if err != nil || !strings.HasSuffix(path, "/sig") {
		t.Fatalf("prompt %q: %v", path, err)
	}
	time.Sleep(time.Second) // the signal is sent meanwhile
	p.answer(id, "once")
	if _, path, err := p.next(time.Second); err == nil {
		t.Errorf("asked again, for %q", path)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "write=ok\n") || !strings.Contains(out.String(), "sig\n") {
		t.Errorf("output:\n%s", out.String())
	}
}

// TestQueuedPrompts checks that concurrent writes share prompts: the same
// path is asked once, and a folder answer settles the writes queued under
// that folder without asking again.
func TestQueuedPrompts(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.home+"/.m2", 0o700); err != nil {
		t.Fatal(err)
	}
	script := `
w() { if echo x > "$HOME/.m2/$1"; then echo "$2=ok"; else echo "$2=denied"; fi; }
w a a1 & w a a2 & w b b1 & w c c1 &
wait
`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	id, path, err := p.next(10 * time.Second)
	if err != nil || !strings.Contains(path, "/.m2/") {
		t.Fatalf("prompt %q: %v\n%s", path, err, out.String())
	}
	time.Sleep(500 * time.Millisecond) // the other writes queue up
	p.answer(id, "temp")
	if _, path, err := p.next(time.Second); err == nil {
		t.Errorf("asked again, for %q", path)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	for _, want := range []string{"a1=ok", "a2=ok", "b1=ok", "c1=ok"} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// TestRenamePerPath checks that a rename between two asked locations asks
// about each path, source first, and that denying the second fails it.
func TestRenamePerPath(t *testing.T) {
	e := newEnv(t)
	if err := os.WriteFile(e.home+"/src", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.root+"/other", 0o700); err != nil {
		t.Fatal(err)
	}
	script := `if mv "$HOME/src" "` + e.root + `/other/dst" 2>/dev/null; then echo mv=ok; else echo mv=denied; fi`
	c := e.cmd(script, "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	for _, st := range []struct{ suffix, reply string }{{"/home/src", "once"}, {"/other/dst", "deny"}} {
		id, path, err := p.next(10 * time.Second)
		if err != nil || !strings.HasSuffix(path, st.suffix) {
			t.Fatalf("prompt %q, want *%s: %v\n%s", path, st.suffix, err, out.String())
		}
		p.answer(id, st.reply)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "mv=denied\n") {
		t.Errorf("output:\n%s", out.String())
	}
	if _, err := os.Stat(e.home + "/src"); err != nil {
		t.Errorf("src moved: %v", err)
	}
}

// TestStrictOnce checks "allow once" in strict mode: the kernel allows the
// syscall that was asked about, and not the same write afterwards.
func TestStrictOnce(t *testing.T) {
	if os.Geteuid() != 0 {
		strictSkip(t, "needs root (go test -exec sudo)")
	}
	if err := lsm.Active(); err != nil {
		strictSkip(t, err.Error())
	}
	e := newEnv(t)
	script := `
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
check once  sh -c 'echo x > "$HOME/once"'
check again sh -c 'echo x > "$HOME/once"'
`
	c := e.cmd(script, "--mode=strict", "--ask=answer", "--timeout=20s")
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	for _, reply := range []string{"once", "deny"} {
		id, path, err := p.next(10 * time.Second)
		if err != nil || !strings.HasSuffix(path, "/once") {
			t.Fatalf("prompt %q: %v\n%s", path, err, out.String())
		}
		p.answer(id, reply)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	for _, want := range []string{"once=ok", "again=denied"} {
		if !strings.Contains(out.String(), want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// strictSkip skips, or fails under HALLPASS_REQUIRE_LSM=1 (see make test-vm).
func strictSkip(t *testing.T, why string) {
	t.Helper()
	if os.Getenv("HALLPASS_REQUIRE_LSM") == "1" {
		t.Fatal("HALLPASS_REQUIRE_LSM=1: " + why)
	}
	t.Skip(why)
}

func readLog(t *testing.T, file string) []logLine {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []logLine
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var e logLine
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		out = append(out, e)
	}
	return out
}

func findLog(lines []logLine, path string) (logLine, bool) {
	for _, l := range lines {
		if l.Path == path {
			return l, true
		}
	}
	return logLine{}, false
}

func TestNoImplicit(t *testing.T) {
	e := newEnv(t)
	if err := os.Mkdir(e.proj+"/out", 0o700); err != nil {
		t.Fatal(err)
	}
	script := `
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=allowed"; else echo "$name=denied"; fi; }
check workdir sh -c 'echo x > inside'
check out     sh -c 'echo x > out/f'
echo "TMPDIR=$TMPDIR"
`
	c := e.cmd(script, "--no-implicit", "--ask=deny", "--allow="+e.proj+"/out", "--allow=/dev/null")
	c.Env = append(c.Env, "TMPDIR=")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"workdir=denied", "out=allowed", "TMPDIR=\n"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestAuditMode(t *testing.T) {
	e := newEnv(t)
	logf := e.root + "/log.jsonl"
	c := e.cmd(`echo x > inside && echo x > "$HOME/outside"`, "--no-implicit", "--ask=allow", "--log="+logf)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := readLog(t, logf)
	for _, p := range []string{e.proj + "/inside", e.home + "/outside"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not written: %v", p, err)
		}
		if l, ok := findLog(lines, p); !ok || l.Decision != "allow" || l.Reason != "audit" {
			t.Errorf("log for %s: %+v (found %v), want allow/audit", p, l, ok)
		}
	}
}

// TestWait checks that a write by a process left behind by the command is
// still mediated and logged with --wait=all, and not with --wait=main.
func TestWait(t *testing.T) {
	for _, wait := range []string{"main", "all"} {
		t.Run(wait, func(t *testing.T) {
			e := newEnv(t)
			logf := e.root + "/log.jsonl"
			script := `(sleep 3; echo x > "$HOME/late") </dev/null >/dev/null 2>&1 & exit 3`
			c := e.cmd(script, "--ask=deny", "--wait="+wait, "--log="+logf)
			start := time.Now()
			out, err := c.CombinedOutput()
			if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
				t.Fatalf("exit: %v (want 3)\n%s", err, out)
			}
			took := time.Since(start)
			time.Sleep(3500 * time.Millisecond) // let a --wait=main orphan try
			l, logged := findLog(readLog(t, logf), e.home+"/late")
			switch wait {
			case "main":
				if took > 2*time.Second {
					t.Errorf("--wait=main took %v: waited for the background process", took)
				}
				if logged {
					t.Errorf("--wait=main logged the background write: %+v", l)
				}
			case "all":
				if took < 3*time.Second {
					t.Errorf("--wait=all returned after %v, before the background process", took)
				}
				if !logged || l.Decision != "deny" {
					t.Errorf("background write: %+v (logged %v), want a deny", l, logged)
				}
				if !strings.Contains(string(out), "still supervising") {
					t.Errorf("no waiting notice in output:\n%s", out)
				}
			}
			if _, err := os.Stat(e.home + "/late"); err == nil {
				t.Error("background write went through")
			}
		})
	}
}
