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
	run("add", "--label", "mine", "deny", "path", e.home+"/secret")
	id := ruleIDOf(t, run("rules"), "deny path "+e.home+"/secret")
	run("edit", id, "deny path "+e.home+"/secret/**")
	out := run("rules")
	if !regexp.MustCompile(`deny path ` + regexp.QuoteMeta(e.home) + `/secret/\*\* +mine`).MatchString(out) {
		t.Errorf("edit lost the label:\n%s", out)
	}
	if out, err := answerCmd(t, e, c, "add", "allow", "path", "/"); err == nil || !strings.Contains(out, `answering "always"`) {
		t.Errorf("hallpass answer add allow path /: %v\n%s", err, out)
	}
	if out, err := answerCmd(t, e, c, "edit", id, "deny path /x"); err == nil || !strings.Contains(out, "no rule "+id) {
		t.Errorf("edit of an edited rule: %v\n%s", err, out)
	}
	run("delete", ruleIDOf(t, out, "deny path "+e.home+"/secret/**"))
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
	m.Write([]byte("deny path " + e.home + "/m\r"))
	waitFor(t, seen("Label (optional): _"), "label field")
	m.Write([]byte("menu\r"))
	waitFor(t, seen("Done."), "the rule added")
	out, err := answerCmd(t, e, c, "rules")
	if err != nil {
		t.Fatal(err)
	}
	id := ruleIDOf(t, out, "deny path "+e.home+"/m")

	m.Write([]byte("e"))
	waitFor(t, seen("Edit rule ID: _"), "ID field")
	m.Write([]byte(id + "\r"))
	waitFor(t, seen(e.home+"/m_"), "the rule to edit")
	m.Write([]byte("/**\r"))
	waitFor(t, seen("/m/**  (menu)"), "the edited rule")

	out, _ = answerCmd(t, e, c, "rules")
	m.Write([]byte("d"))
	waitFor(t, seen("Delete rule ID: _"), "ID field")
	m.Write([]byte(ruleIDOf(t, out, "deny path "+e.home+"/m/**") + "\r"))
	waitFor(t, func() bool { return !strings.Contains(scr.text(), "/m/**") }, "the rule deleted")
	m.Write([]byte("q"))
	waitFor(t, func() bool { return !strings.Contains(scr.text(), "[a] add") }, "the menu closed")
	if out, _ := answerCmd(t, e, c, "rules"); strings.Contains(out, e.home+"/m") {
		t.Errorf("rule left:\n%s", out)
	}
}
