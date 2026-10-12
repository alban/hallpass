// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var hallpassBin string

func TestMain(m *testing.M) {
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
	sock := fmt.Sprintf("%s/hallpass/%d.sock", e.runtime, c.Process.Pid)
	var conn net.Conn
	var err error
	for i := 0; i < 100; i++ {
		if conn, err = net.Dial("unix", sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		c.Process.Kill()
		t.Fatalf("dial %s: %v", sock, err)
	}
	defer conn.Close()
	rd := bufio.NewReader(conn)
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
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("read prompt: %v\n%s", err, out.String())
		}
		var req struct {
			ID    uint64
			Path  string
			Scope string
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PROMPT ")), &req); err != nil {
			t.Fatalf("bad prompt %q: %v", line, err)
		}
		if !strings.HasSuffix(req.Path, st.suffix) || !strings.HasSuffix(req.Scope, st.scope) {
			t.Errorf("prompt for %q (scope %q), want *%s (scope *%s)", req.Path, req.Scope, st.suffix, st.scope)
		}
		// A stale answer must be ignored.
		fmt.Fprintf(conn, "%d once\n", req.ID+1000)
		fmt.Fprintf(conn, "%d %s\n", req.ID, st.reply)
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
