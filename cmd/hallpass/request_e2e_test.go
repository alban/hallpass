// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requestBin returns the hallpass-request helper: HALLPASS_REQUEST_BIN, or
// cmd/hallpass-request built with musl-gcc in e.root. It skips without
// musl-gcc.
func requestBin(t *testing.T, e env) string {
	t.Helper()
	if bin := os.Getenv("HALLPASS_REQUEST_BIN"); bin != "" {
		return bin
	}
	cc, err := exec.LookPath("musl-gcc")
	if err != nil {
		t.Skip("no musl-gcc (musl-tools), and no HALLPASS_REQUEST_BIN")
	}
	bin := filepath.Join(e.root, "bin", "hallpass-request")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-static", "-Os", "-Wall", "-Wextra", "-Werror", "-o", bin, "../hallpass-request/hallpass-request.c").CombinedOutput(); err != nil {
		t.Fatalf("musl-gcc: %v\n%s", err, out)
	}
	return bin
}

// requestScript defines r: `r NAME ARGS...` runs hallpass-request ARGS and
// prints "NAME rc=CODE MESSAGE".
func requestScript(bin string) string {
	return advanceScript + `
r() { name=$1; shift; m=$('` + bin + `' "$@" 2>&1); echo "$name rc=$? $m"; }
`
}

// requestWant returns the start of the line r prints for an exit code.
func requestWant(name string, code int, msg string) string {
	return fmt.Sprintf("%s rc=%d hallpass-request: %s", name, code, msg)
}

func requestCheck(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, "\n"+want) && !strings.HasPrefix(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

// TestRequestHelper asks with hallpass-request for a folder whose name
// needs percent-encoding, is granted it, and checks each answer.
func TestRequestHelper(t *testing.T) {
	advanceModes(t, func(t *testing.T, mode string) {
		e := newEnv(t)
		bin := requestBin(t, e)
		dir := e.home + "/a b&c%d+e=f#g;h"
		reason := "why? a&b=c%d+e #f/** é\nnext"
		script := requestScript(bin) + `
r check1 check write "$DIR/**" --for 10m
r grant write "$DIR/**" --for=10m --reason "$REASON"
check write sh -c 'mkdir "$DIR" "$DIR/sub" && echo x > "$DIR/sub/f"'
r again write "$DIR/**" --for 10m
(cd "$DIR" && r relative write sub/f --for 5m)
r check2 check write "$DIR/**"
r deny write "$HOME/no"
r badfor write "$HOME/x" --for nope
r glob write "$HOME/x*"
r long write "/$(printf %5000s | tr ' ' a)"
r usage
r op read /x
r two write /x /y
`
		c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s", "--allow-exec="+bin)
		c.Env = append(c.Env, "DIR="+dir, "REASON="+reason)
		var out strings.Builder
		c.Stdout, c.Stderr = &out, &out
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		p := dialPrompts(t, e, c)
		r, err := p.nextRequest(10 * time.Second)
		if err != nil {
			t.Fatalf("prompt: %v\n%s", err, out.String())
		}
		pr := r.GetPrompt()
		if a := r.GetAdvance(); !a.GetTree() || a.GetFor().AsDuration() != 10*time.Minute || a.GetReason() != reason {
			t.Errorf("advance %v", a)
		}
		if !pr.GetAdvance() || pr.GetPath() != dir+"/**" || pr.GetOp() != "write" {
			t.Errorf("prompt %v", pr)
		}
		p.answer(r.Id, "grant")
		id, path, err := p.next(10 * time.Second)
		if err != nil || path != e.home+"/no" {
			t.Fatalf("prompt %q: %v\n%s", path, err, out.String())
		}
		p.answer(id, "deny")
		if err := c.Wait(); err != nil {
			t.Fatalf("hallpass: %v\n%s", err, out.String())
		}
		requestCheck(t, out.String(),
			requestWant("check1", 5, "not allowed yet"),
			requestWant("grant", 0, "granted"),
			"write=ok",
			requestWant("again", 1, "already allowed"),
			requestWant("relative", 1, "already allowed"),
			requestWant("check2", 1, "allowed"),
			requestWant("deny", 3, "denied"),
			requestWant("badfor", 6, "invalid request"),
			requestWant("glob", 6, "invalid request"),
			requestWant("long", 6, "invalid request: too long"),
			"usage rc=2 usage: hallpass-request",
			requestWant("op", 2, "unknown operation read"),
			requestWant("two", 2, "one path only"),
		)
		if b, err := os.ReadFile(dir + "/sub/f"); err != nil || string(b) != "x\n" {
			t.Errorf("sub/f: %q, %v", b, err)
		}
	})
}

// TestRequestHelperAnswers checks the other answers, that running the
// helper needs an exec rule like any program, and the helper without
// hallpass.
func TestRequestHelperAnswers(t *testing.T) {
	advanceModes(t, func(t *testing.T, mode string) {
		e := newEnv(t)
		bin := requestBin(t, e)
		script := requestScript(bin) + `r req write "$HOME/x" --reason test` + "\n"
		for _, tc := range []struct {
			flags []string
			want  string
		}{
			{[]string{"--prompt=deny"}, requestWant("req", 3, "denied")},
			{[]string{"--prompt=answer", "--timeout=1s"}, requestWant("req", 4, "denied: nobody answered in time")},
			{[]string{"--prompt=allow"}, requestWant("req", 0, "granted")},
			{[]string{"--prompt=answer", "--timeout=1s", "--mediate=exec"}, requestWant("req", 7, "files are not mediated")},
		} {
			c := e.cmd(script, append([]string{"--mode=" + mode, "--allow-exec=" + bin}, tc.flags...)...)
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %v\n%s", tc.flags, err, out)
			}
			t.Run(strings.Join(tc.flags, " "), func(t *testing.T) { requestCheck(t, string(out), tc.want) })
		}

		// No implicit exec rule: without --allow-exec, the helper itself
		// is asked about, here denied, and the shell fails to run it.
		c := e.cmd(script, "--mode="+mode, "--prompt=deny")
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if !strings.Contains(string(out), "req rc=126 ") {
			t.Errorf("helper without an exec rule: want rc=126:\n%s", out)
		}
	})

	e := newEnv(t)
	bin := requestBin(t, e)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"write", "/x"}, 8, "hallpass-request: not running under hallpass"},
		{[]string{"check", "write", "/x"}, 8, "hallpass-request: not running under hallpass"},
		// Too long: refused before the execve, which would fail with
		// ENOENT here.
		{[]string{"write", "/x", "--reason", strings.Repeat("é", 1000)}, 6, "hallpass-request: invalid request: too long"},
		{nil, 2, "usage: hallpass-request [check] write PATH"},
		{[]string{"--help"}, 0, "usage: hallpass-request [check] write PATH"},
		{[]string{"write", "/x", "--for"}, 2, "hallpass-request: --for needs a value"},
		{[]string{"write", "/x", "--force"}, 2, "hallpass-request: unknown option --force"},
	} {
		c := exec.Command(bin, tc.args...)
		out, _ := c.CombinedOutput()
		if code := c.ProcessState.ExitCode(); code != tc.code || !strings.HasPrefix(string(out), tc.want) {
			t.Errorf("%q: exit %d, %q; want %d, %q", tc.args, code, out, tc.code, tc.want)
		}
	}
}
