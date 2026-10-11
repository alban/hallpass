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

// newEnv creates a fake $HOME outside /tmp (which the default policy allows).
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
		"tmp": "allowed",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
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

func TestAnswerSocket(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.home+"/.m2/r", 0o700); err != nil {
		t.Fatal(err)
	}
	c := e.cmd(`echo a > "$HOME/.m2/a" && echo a=ok; echo a2 > "$HOME/.m2/r/a2" && echo a2=ok; echo b > "$HOME/b" 2>/dev/null && echo b=ok || echo b=denied`,
		"--ask=answer", "--timeout=20s")
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
	// "folder-temp" on ~/.m2/a grants ~/.m2 for 5 minutes, so a2 goes
	// through without prompting; the next prompt is for b.
	for _, reply := range []string{"folder-temp", "deny"} {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatalf("read prompt: %v", err)
		}
		var req struct {
			ID   uint64
			Path string
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PROMPT ")), &req); err != nil {
			t.Fatalf("bad prompt %q: %v", line, err)
		}
		// A stale answer must be ignored.
		fmt.Fprintf(conn, "%d once\n", req.ID+1000)
		fmt.Fprintf(conn, "%d %s\n", req.ID, reply)
	}
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "a=ok") || !strings.Contains(out.String(), "a2=ok") || !strings.Contains(out.String(), "b=denied") {
		t.Errorf("unexpected output:\n%s", out.String())
	}
	if _, err := os.Stat(e.home + "/b"); err == nil {
		t.Error("b was created despite deny")
	}
}
