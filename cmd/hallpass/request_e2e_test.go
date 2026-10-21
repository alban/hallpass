// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/alban/hallpass/api/session/v1"
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
			requestWant("two", 2, "one target only"),
		)
		if b, err := os.ReadFile(dir + "/sub/f"); err != nil || string(b) != "x\n" {
			t.Errorf("sub/f: %q, %v", b, err)
		}
	})
}

// TestRequestExecNet asks with hallpass-request for a program and a
// network destination, is granted them, uses them without being asked,
// and gives them back; a release never removes the user's own rules.
func TestRequestExecNet(t *testing.T) {
	advanceModes(t, func(t *testing.T, mode string) {
		e := newEnv(t)
		bin := requestBin(t, e)
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		tool := e.root + "/tools/tool"
		if err := os.MkdirAll(filepath.Dir(tool), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tool, []byte("#!/bin/sh\necho tool=ran\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		dest := fmt.Sprintf("tcp:127.0.0.1:%d", listenTCP(t))
		script := requestScript(bin) + `
H() { HALLPASS_E2E_HELPER=net "$HP_SELF" "$@"; }
r echeck check exec "$TOOL"
r egrant exec "$TOOL" --for 10m --reason build
"$TOOL"
r eagain exec "$TOOL" --for 5m
r erel release exec "$TOOL"
r erel2 release exec "$TOOL"
r echeck2 check exec "$TOOL"
r ewritable exec "$PWD/run.sh"
r cgrant connect "$DEST" --reason push
H tcp connect "${DEST#tcp:}"
r ccheck check connect "$DEST"
r crel release connect "$DEST"
r ccheck2 check connect "$DEST"
r call connect all
r chost connect example.com:443
r urel release exec "$BIN"
r uwrel release write "$HOME/proj/**"
r ucheck check exec "$BIN"
`
		c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s", "--mediate=files,exec,network", "--allow-exec="+bin, "--log="+e.root+"/log")
		c.Env = append(c.Env, "TOOL="+tool, "DEST="+dest, "BIN="+bin, "HP_SELF="+self)
		var out strings.Builder
		c.Stdout, c.Stderr = &out, &out
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		p := dialPrompts(t, e, c)
		next := func() (*pb.Request, *pb.Prompt) {
			t.Helper()
			r, err := p.nextRequest(10 * time.Second)
			if err != nil {
				c.Process.Kill()
				t.Fatalf("prompt: %v\n%s", err, out.String())
			}
			return r, r.GetPrompt()
		}

		r, pr := next()
		if a := r.GetAdvance(); a.GetTree() || a.GetFor().AsDuration() != 10*time.Minute || a.GetWritable() || r.GetObjects()[0].GetPath().GetPath() != tool {
			t.Errorf("exec advance %v", r)
		}
		if !pr.GetAdvance() || pr.GetOp() != "exec" || pr.GetPath() != tool || pr.GetReason() != "build" || pr.GetWarn() != "" {
			t.Errorf("exec prompt %v", pr)
		}
		p.answer(r.Id, "grant")

		r, pr = next()
		if !r.GetAdvance().GetWritable() || pr.GetOp() != "exec" || pr.GetPath() != e.proj+"/run.sh" || !strings.Contains(pr.GetWarn(), "writable") {
			t.Errorf("writable prompt %v %v", r.GetAdvance(), pr)
		}
		p.answer(r.Id, "deny")

		r, pr = next()
		if a := r.GetAdvance(); a.GetDest() != dest || len(r.GetObjects()) != 0 {
			t.Errorf("connect advance %v", r)
		}
		if !pr.GetAdvance() || pr.GetOp() != "connect to" || pr.GetPath() != dest || pr.GetReason() != "push" {
			t.Errorf("connect prompt %v", pr)
		}
		p.answer(r.Id, "grant")

		if err := c.Wait(); err != nil {
			t.Fatalf("hallpass: %v\n%s", err, out.String())
		}
		requestCheck(t, out.String(),
			requestWant("echeck", 5, "not allowed yet: a request, or trying to run it"),
			requestWant("egrant", 0, "granted"),
			"tool=ran",
			requestWant("eagain", 1, "already allowed"),
			requestWant("erel", 0, "released"),
			requestWant("erel2", 10, "no such grant"),
			requestWant("echeck2", 5, "not allowed yet"),
			requestWant("ewritable", 3, "denied by the user or a rule: do not run it"),
			requestWant("cgrant", 0, "granted"),
			"tcp=ok",
			requestWant("ccheck", 1, "allowed"),
			requestWant("crel", 0, "released"),
			requestWant("ccheck2", 5, "not allowed yet"),
			requestWant("call", 6, "invalid request: DEST"),
			requestWant("chost", 6, "invalid request: DEST"),
			requestWant("urel", 10, "no such grant"),
			requestWant("uwrel", 10, "no such grant"),
			requestWant("ucheck", 1, "allowed"),
			"hallpass: hallpass-request (pid ",
		)
		if !strings.Contains(out.String(), ") gave back exec "+tool+"\n") || !strings.Contains(out.String(), ") gave back connect to "+dest+"\n") {
			t.Errorf("no release notice:\n%s", out.String())
		}
		log, err := os.ReadFile(e.root + "/log")
		if err != nil || !strings.Contains(string(log), `"path":"`+tool+`","decision":"release"`) || !strings.Contains(string(log), `"net":"`+dest+`","decision":"release"`) {
			t.Errorf("--log: %v\n%s", err, log)
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
		script := requestScript(bin) + `
r req write "$HOME/x" --reason test
r rx exec "$HOME/bin/x"
r rn connect 127.0.0.1:1
`
		for _, tc := range []struct {
			flags []string
			want  []string
		}{
			{[]string{"--prompt=deny"}, []string{requestWant("req", 3, "denied"), requestWant("rx", 3, "denied"), requestWant("rn", 7, "connect is not mediated")}},
			{[]string{"--prompt=deny", "--mediate=files,exec,network"}, []string{requestWant("rn", 3, "denied")}},
			{[]string{"--prompt=answer", "--timeout=1s"}, []string{requestWant("req", 4, "denied: nobody answered in time")}},
			{[]string{"--prompt=allow"}, []string{requestWant("req", 0, "granted"), requestWant("rx", 0, "granted"), requestWant("rn", 7, "connect is not mediated")}},
			{[]string{"--prompt=allow", "--mediate=files,exec,network"}, []string{requestWant("rn", 0, "granted")}},
			{[]string{"--prompt=answer", "--timeout=1s", "--mediate=exec"}, []string{requestWant("req", 7, "write is not mediated")}},
			{[]string{"--prompt=deny", "--mediate=files"}, []string{requestWant("rx", 7, "exec is not mediated")}},
		} {
			flags := []string{"--mode=" + mode}
			if !slices.Contains(tc.flags, "--mediate=files") {
				// Refused without exec mediated.
				flags = append(flags, "--allow-exec="+bin)
			}
			c := e.cmd(script, append(flags, tc.flags...)...)
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %v\n%s", tc.flags, err, out)
			}
			t.Run(strings.Join(tc.flags, " "), func(t *testing.T) { requestCheck(t, string(out), tc.want...) })
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
		{nil, 2, "usage: hallpass-request [check] write|exec PATH"},
		{[]string{"--help"}, 0, "usage: hallpass-request [check] write|exec PATH"},
		{[]string{"write", "/x", "--for"}, 2, "hallpass-request: --for needs a value"},
		{[]string{"write", "/x", "--force"}, 2, "hallpass-request: unknown option --force"},
		{[]string{"exec", "/x"}, 8, "hallpass-request: not running under hallpass"},
		{[]string{"exec", "hallpass-no-such-program"}, 6, "hallpass-request: invalid request: hallpass-no-such-program not found in $PATH"},
		{[]string{"exec", "@shells"}, 2, "hallpass-request: a group of programs cannot be asked for"},
		{[]string{"connect", "tcp:10.0.0.1:443"}, 8, "hallpass-request: not running under hallpass"},
		{[]string{"release", "connect", "tcp:10.0.0.1:443"}, 8, "hallpass-request: not running under hallpass"},
		{[]string{"release", "write", "/x", "--for", "1m"}, 2, "hallpass-request: release takes no --for or --reason"},
		{[]string{"check", "release", "write", "/x"}, 2, "hallpass-request: unknown operation release"},
		{[]string{"connect", "/x", "/y"}, 2, "hallpass-request: one target only"},
	} {
		c := exec.Command(bin, tc.args...)
		out, _ := c.CombinedOutput()
		if code := c.ProcessState.ExitCode(); code != tc.code || !strings.HasPrefix(string(out), tc.want) {
			t.Errorf("%q: exit %d, %q; want %d, %q", tc.args, code, out, tc.code, tc.want)
		}
	}
}
