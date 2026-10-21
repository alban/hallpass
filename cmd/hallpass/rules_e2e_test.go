// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// answerCmd runs `hallpass answer PID args...` on the session of c.
func answerCmd(t *testing.T, e env, c *exec.Cmd, args ...string) (string, error) {
	t.Helper()
	a := exec.Command(hallpassBin, append([]string{"answer", strconv.Itoa(c.Process.Pid)}, args...)...)
	a.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+e.runtime)
	out, err := a.CombinedOutput()
	return string(out), err
}

// ruleIDOf returns the ID of the rule listed by `hallpass answer rules` in
// out whose spec is spec.
func ruleIDOf(t *testing.T, out, spec string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^(\d+) +` + regexp.QuoteMeta(spec) + `( |$)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("%q not listed:\n%s", spec, out)
	}
	return m[1]
}

// TestAnswerRuleCommands lists, adds, edits and deletes a session's rules
// with `hallpass answer`.
func TestAnswerRuleCommands(t *testing.T) {
	e := newEnv(t)
	c := e.cmd(`sleep 60`, "--prompt=answer")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	dialPrompts(t, e, c)

	run := func(args ...string) string {
		t.Helper()
		out, err := answerCmd(t, e, c, args...)
		if err != nil {
			t.Fatalf("hallpass answer %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	run("add", "--label", "mine", "deny", "write", e.home+"/secret")
	id := ruleIDOf(t, run("rules"), "deny write "+e.home+"/secret")
	run("edit", id, "deny write "+e.home+"/secret/**")
	out := run("rules")
	if !regexp.MustCompile(`deny write ` + regexp.QuoteMeta(e.home) + `/secret/\*\* +mine`).MatchString(out) {
		t.Errorf("edit lost the label:\n%s", out)
	}
	if out, err := answerCmd(t, e, c, "add", "allow", "write", "/"); err == nil || !strings.Contains(out, `answering "always"`) {
		t.Errorf("hallpass answer add allow write /: %v\n%s", err, out)
	}
	if out, err := answerCmd(t, e, c, "edit", id, "deny write /x"); err == nil || !strings.Contains(out, "no rule "+id) {
		t.Errorf("edit of an edited rule: %v\n%s", err, out)
	}
	run("delete", ruleIDOf(t, out, "deny write "+e.home+"/secret/**"))
	if out := run("rules"); strings.Contains(out, "/secret") {
		t.Errorf("rule not deleted:\n%s", out)
	}
	if out, err := answerCmd(t, e, c, "frobnicate"); err == nil || !strings.Contains(out, "usage") {
		t.Errorf("bad command: %v\n%s", err, out)
	}
}

// TestTerminalMenuRules adds a rule from the Ctrl-] menu, then edits and
// deletes it.
func TestTerminalMenuRules(t *testing.T) {
	e := newEnv(t)
	m, scr, c, _ := runTerm(t, e, `echo ready; exec sleep 60`)
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	waitFor(t, func() bool { return strings.Contains(scr.text(), "ready") }, "the command")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("screen:\n%s", scr.text())
		}
	})
	seen := func(s string) func() bool { return func() bool { return strings.Contains(scr.text(), s) } }

	m.Write([]byte{0x1d})
	waitFor(t, seen("[r] edit the rules"), "menu")
	m.Write([]byte("r"))
	waitFor(t, seen("[a] add"), "rules menu")
	m.Write([]byte("a"))
	waitFor(t, seen("Rule: _"), "rule field")
	m.Write([]byte("deny write " + e.home + "/m\r"))
	waitFor(t, seen("Label (optional): _"), "label field")
	m.Write([]byte("menu\r"))
	waitFor(t, seen("Done."), "the rule added")
	out, err := answerCmd(t, e, c, "rules")
	if err != nil {
		t.Fatal(err)
	}
	id := ruleIDOf(t, out, "deny write "+e.home+"/m")

	m.Write([]byte("e"))
	waitFor(t, seen("Edit rule ID: _"), "ID field")
	m.Write([]byte(id + "\r"))
	waitFor(t, seen(e.home+"/m_"), "the rule to edit")
	m.Write([]byte("/**\r"))
	waitFor(t, seen("/m/**  (menu)"), "the edited rule")

	out, _ = answerCmd(t, e, c, "rules")
	m.Write([]byte("d"))
	waitFor(t, seen("Delete rule ID: _"), "ID field")
	m.Write([]byte(ruleIDOf(t, out, "deny write "+e.home+"/m/**") + "\r"))
	waitFor(t, func() bool { return !strings.Contains(scr.text(), "/m/**") }, "the rule deleted")
	m.Write([]byte("q"))
	waitFor(t, func() bool { return !strings.Contains(scr.text(), "[a] add") }, "the menu closed")
	if out, _ := answerCmd(t, e, c, "rules"); strings.Contains(out, e.home+"/m") {
		t.Errorf("rule left:\n%s", out)
	}
}

// TestRuleEditEnforced adds a deny rule with hallpass answer while the
// session runs, moves it to another file and deletes it, checking writes
// after each change: in strict mode, the edits reach the kernel.
func TestRuleEditEnforced(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			script := `
check() { if echo x > "$1" 2>/dev/null; then echo "$2 $1=ok"; else echo "$2 $1=denied"; fi; rm -f "$1" 2>/dev/null; }
for s in 1 2 3; do
	while [ ! -e go$s ]; do sleep 0.05; done
	check a $s
	check b $s
	touch done$s
done
`
			c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s")
			var out strings.Builder
			c.Stdout, c.Stderr = &out, &out
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
			dialPrompts(t, e, c)
			run := func(args ...string) string {
				t.Helper()
				out, err := answerCmd(t, e, c, args...)
				if err != nil {
					t.Fatalf("hallpass answer %s: %v\n%s", strings.Join(args, " "), err, out)
				}
				return out
			}
			step := func(s int) {
				t.Helper()
				if err := os.WriteFile(e.proj+"/go"+strconv.Itoa(s), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 400; i++ {
					if _, err := os.Stat(e.proj + "/done" + strconv.Itoa(s)); err == nil {
						return
					}
					time.Sleep(25 * time.Millisecond)
				}
				t.Fatalf("step %d timed out", s)
			}

			a, b := e.proj+"/a", e.proj+"/b"
			run("add", "deny", "write", a)
			step(1)
			if mode == "strict" {
				if out, err := answerCmd(t, e, c, "add", "ask", "exec", "/bin/true"); err == nil || !strings.Contains(out, "not enforceable in strict mode: ask exec ") {
					t.Errorf("hallpass answer add ask exec: %v\n%s", err, out)
				}
			}
			run("edit", ruleIDOf(t, run("rules"), "deny write "+a), "deny write "+b)
			step(2)
			run("delete", ruleIDOf(t, run("rules"), "deny write "+b))
			step(3)
			if err := c.Wait(); err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out.String())
			}
			for _, want := range []string{"1 a=denied", "1 b=ok", "2 a=ok", "2 b=denied", "3 a=ok", "3 b=ok"} {
				if !strings.Contains(out.String(), want+"\n") {
					t.Errorf("output lacks %q:\n%s", want, out.String())
				}
			}
		})
	}
}
