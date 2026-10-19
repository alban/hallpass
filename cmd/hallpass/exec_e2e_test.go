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

// progs copies the true program to each name under dir, and returns dir.
func progs(t *testing.T, dir string, names ...string) string {
	t.Helper()
	src, err := exec.LookPath("true")
	if err != nil {
		t.Skip(err)
	}
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		p := filepath.Join(dir, n)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// outputMap parses the name=value lines of out.
func outputMap(out string) map[string]string {
	got := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	return got
}

const checkExec = `check() { name=$1; shift; if "$@" >/dev/null 2>&1; then echo "$name=allowed"; else echo "$name=denied"; fi; }
`

// TestExecRules checks which programs run without asking: the command and
// the groups of --allow-exec (ls), --allow-exec, --deny-exec, and #!
// interpreters; the others are asked about (denied here), with the shell's
// exit code 126.
func TestExecRules(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			bin := progs(t, e.root+"/bin", "allowed", "other", "denied", "tree/a", "tree/b")
			if err := os.WriteFile(bin+"/script", []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			// Its interpreter is not allowed.
			if err := os.WriteFile(bin+"/script2", []byte("#!"+bin+"/other\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			script := checkExec + fmt.Sprintf(`
cd %s
check ls      ls /
check allowed ./allowed
check other   ./other
check denied  ./denied
check tree    ./tree/a
check treeb   ./tree/b
check script  ./script
check script2 ./script2
check missing ./missing
./other 2>/dev/null; echo "rc=$?"
`, bin)
			c := e.cmd(script, "--mode="+mode, "--prompt=deny",
				"--allow-exec="+bin+"/allowed", "--allow-exec="+bin+"/tree/**", "--allow-exec="+bin+"/script", "--allow-exec="+bin+"/script2",
				"--deny-exec="+bin+"/denied", "--deny-exec="+bin+"/tree/b")
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out)
			}
			got := outputMap(string(out))
			for k, v := range map[string]string{
				"ls": "allowed", "allowed": "allowed", "other": "denied", "denied": "denied",
				"tree": "allowed", "treeb": "denied", "script": "allowed", "script2": "denied", "missing": "denied", "rc": "126",
			} {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q\n%s", k, got[k], v, out)
				}
			}
		})
	}
}

// TestExecGroups: the command and the implicit groups run without asking;
// with --no-implicit, only the command, unless a group is allowed; an
// unknown group is an error.
func TestExecGroups(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			script := checkExec + "check ls ls /\ncheck cat cat /dev/null\necho end=$?"
			bare := []string{"--no-implicit", "--allow-path=/dev/null"}
			for _, tc := range []struct {
				flags   []string
				ls, cat string
			}{
				{nil, "allowed", "allowed"},
				{bare, "denied", "denied"},
				{append(bare, "--allow-exec=@coreutils"), "allowed", "allowed"},
				{append(bare, "--allow-exec=@search,@coreutils"), "allowed", "allowed"},
				// A group of one's own, and one replacing a built-in group.
				{append(bare, "--group=@mine=ls", "--allow-exec=@mine"), "allowed", "denied"},
				{append(bare, "--group=@coreutils=cat", "--allow-exec=@coreutils"), "denied", "allowed"},
				// Replacing an implicit group changes what is implicit.
				{[]string{"--group=@coreutils=cat"}, "denied", "allowed"},
			} {
				c := e.rawCmd(script, append([]string{"--mode=" + mode, "--prompt=deny"}, tc.flags...)...)
				out, err := c.CombinedOutput()
				if err != nil {
					t.Fatalf("%v: hallpass: %v\n%s", tc.flags, err, out)
				}
				if got := outputMap(string(out)); got["ls"] != tc.ls || got["cat"] != tc.cat || got["end"] != "0" {
					t.Errorf("%v: got %v\n%s", tc.flags, got, out)
				}
			}
			out, err := e.rawCmd("true", "--mode="+mode, "--allow-exec=@nope").CombinedOutput()
			if err == nil || !strings.Contains(string(out), "unknown group") {
				t.Errorf("@nope: %v\n%s", err, out)
			}
			out, err = e.rawCmd("true", "--mode="+mode, "--group=@Bad=ls").CombinedOutput()
			if err == nil || !strings.Contains(string(out), "--group") {
				t.Errorf("@Bad: %v\n%s", err, out)
			}
		})
	}
}

// TestExecGroupsPrint: the rules list a group by name and count.
func TestExecGroupsPrint(t *testing.T) {
	e := newEnv(t)
	c := exec.Command(hallpassBin, "policy", "--allow-exec=@coreutils", "--", "sh")
	c.Env = append(os.Environ(), "HOME="+e.home)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "@coreutils (") || !strings.Contains(string(out), " programs)") || strings.Contains(string(out), "/ls\n") {
		t.Errorf("policy:\n%s", out)
	}
	c = exec.Command(hallpassBin, "policy", "--group=@mine=ls,cat", "--allow-exec=@mine", "--", "sh")
	c.Env = append(os.Environ(), "HOME="+e.home)
	if out, err = c.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "@mine (ls, cat: 2 programs)") {
		t.Errorf("policy with --group:\n%s", out)
	}
	for _, noImplicit := range []bool{false, true} {
		args := []string{"policy", "--", "sh"}
		if noImplicit {
			args = []string{"policy", "--no-implicit", "--", "sh"}
		}
		c = exec.Command(hallpassBin, args...)
		c.Env = append(os.Environ(), "HOME="+e.home)
		if out, err = c.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if got := strings.Contains(string(out), "@git ("); got == noImplicit {
			t.Errorf("--no-implicit %t: @git listed %t:\n%s", noImplicit, got, out)
		}
	}
}

// TestExecNotMediated: with --mediate=files, programs run without rules.
func TestExecNotMediated(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			bin := progs(t, e.root+"/bin", "other")
			c := e.cmd(checkExec+"check other "+bin+"/other", "--mode="+mode, "--prompt=deny", "--mediate=files")
			out, err := c.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "other=allowed\n") {
				t.Errorf("%v\n%s", err, out)
			}
			c = e.cmd("true", "--mediate=files", "--allow-exec="+bin+"/other")
			if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "exec in mediate") {
				t.Errorf("--allow-exec without exec mediated: %v\n%s", err, out)
			}
		})
	}
}

// TestExecPrompt answers exec prompts: "once" runs the program once (a
// one-time grant in strict mode), "always" adds a rule for that program
// only, "deny" denies with EACCES.
func TestExecPrompt(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			bin := progs(t, e.root+"/bin", "once", "always", "always2", "no")
			script := checkExec + fmt.Sprintf(`
cd %s
check once1   ./once
check always1 ./always
check always2 ./always
check no      ./no
check once2   ./once
`, bin)
			c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s")
			var out strings.Builder
			c.Stdout, c.Stderr = &out, &out
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			p := dialPrompts(t, e, c)
			for _, st := range []struct{ path, reply string }{
				{bin + "/once", "once"},
				{bin + "/always", "always"},
				{bin + "/no", "deny"},
				{bin + "/once", "deny"},
			} {
				req, err := p.nextRequest(10 * time.Second)
				if err != nil {
					t.Fatalf("read prompt: %v\n%s", err, out.String())
				}
				pr := req.Prompt
				if pr.GetOp() != "exec" || pr.GetPath() != st.path || pr.GetScope() != st.path {
					t.Errorf("prompt %v, want exec %s", pr, st.path)
				}
				p.answer(req.Id, st.reply)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out.String())
			}
			got := outputMap(out.String())
			for k, v := range map[string]string{"once1": "allowed", "always1": "allowed", "always2": "allowed", "no": "denied", "once2": "denied"} {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q", k, got[k], v)
				}
			}
			if t.Failed() {
				t.Logf("output:\n%s", out.String())
			}
		})
	}
}

// TestExecPromptGroup: a prompt for a program of a group offers it, and
// "group" lets the other programs of the group run without asking.
func TestExecPromptGroup(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			bin := progs(t, e.root+"/bin", "other")
			script := checkExec + "check ls ls /\ncheck cat cat /dev/null\ncheck other " + bin + "/other\n"
			c := e.rawCmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s", "--no-implicit", "--allow-path=/dev/null", "--allow-tty")
			var out strings.Builder
			c.Stdout, c.Stderr = &out, &out
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			p := dialPrompts(t, e, c)
			req, err := p.nextRequest(10 * time.Second)
			if err != nil {
				t.Fatalf("read prompt: %v\n%s", err, out.String())
			}
			if g := req.Prompt.GetGroup(); !strings.HasPrefix(g, "@coreutils (") || !strings.HasSuffix(req.Prompt.GetPath(), "/ls") {
				t.Errorf("prompt %v, want ls in @coreutils", req.Prompt)
			}
			p.answer(req.Id, "group")
			// cat is in the group: the next prompt is about other, in no group.
			req, err = p.nextRequest(10 * time.Second)
			if err != nil {
				t.Fatalf("read prompt: %v\n%s", err, out.String())
			}
			if req.Prompt.GetPath() != bin+"/other" || req.Prompt.GetGroup() != "" {
				t.Errorf("prompt %v, want %s without a group", req.Prompt, bin+"/other")
			}
			p.answer(req.Id, "deny")
			if err := c.Wait(); err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out.String())
			}
			got := outputMap(out.String())
			for k, v := range map[string]string{"ls": "allowed", "cat": "allowed", "other": "denied"} {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q\n%s", k, got[k], v, out.String())
				}
			}
		})
	}
}
