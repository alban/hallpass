// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"testing"
	"time"
)

func newTestEngine() *Engine {
	home := "/home/u"
	e := New(home, "/home/u/src/proj", append(DefaultAllows(), "/home/u/.cache/go-build"), nil)
	e.SetTmpdir("/home/u/tmp/hallpass-1")
	return e
}

func TestEval(t *testing.T) {
	e := newTestEngine()
	for _, tc := range []struct {
		path string
		want Decision
	}{
		{"/home/u/src/proj/main.go", Allow},
		{"/home/u/src/proj", Allow},
		{"/home/u/src/projX/main.go", Ask}, // prefix match is per component
		{"/home/u/.cache/go-build/ab/x", Allow},
		{"/tmp/x", Ask},
		{"/dev/shm/x", Ask},
		{"/home/u/tmp/hallpass-1/x", Allow},
		{"/dev/null", Allow},
		{"/dev/ptmx", Allow},
		{"/dev/pts/3", Ask}, // another session's terminal
		{"/home/u/.ssh/authorized_keys", Ask},
		{"/home/u/.ssh", Ask},
		{"/home/u/.sshx", Ask},
		{"/home/u/.bashrc", Ask},
		{"/etc/passwd", Ask},
	} {
		if got := e.Eval(tc.path); got != tc.want {
			t.Errorf("Eval(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestWarn(t *testing.T) {
	e := newTestEngine()
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/home/u/.ssh/authorized_keys", "SSH keys"},
		{"/home/u/.ssh", "SSH keys"},
		{"/home/u/.aws/credentials", "AWS credentials"},
		{"/home/u/.config/gh/hosts.yml", "GitHub CLI credentials"},
		{"/home/u/.sshx", ""},
		{"/home/u/.bashrc", ""},
		{"/home/u/src/proj/main.go", ""},
	} {
		if got := e.Warn(tc.path); got != tc.want {
			t.Errorf("Warn(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestAllowDevice(t *testing.T) {
	e := newTestEngine()
	if got := e.Eval("/dev/pts/7"); got != Ask {
		t.Errorf("before AllowDevice: %v, want Ask", got)
	}
	e.AllowDevice("/dev/pts/7")
	if got := e.Eval("/dev/pts/7"); got != Allow {
		t.Errorf("after AllowDevice: %v, want Allow", got)
	}
	if got := e.Eval("/dev/pts/8"); got != Ask {
		t.Errorf("other terminal: %v, want Ask", got)
	}
}

func TestDenyWinsOverWorkdir(t *testing.T) {
	e := New("/home/u", "/home/u/secret", nil, []string{"/home/u/secret"})
	if got := e.Eval("/home/u/secret/config"); got != Deny {
		t.Errorf("got %v, want Deny", got)
	}
}

func TestSessionAnswers(t *testing.T) {
	e := newTestEngine()
	e.AllowFolder("/home/u/.npm")
	if got := e.Eval("/home/u/.npm/_cacache/x"); got != Allow {
		t.Errorf("after AllowFolder: %v", got)
	}
	e.DenyPath("/home/u/.bashrc")
	if got := e.Eval("/home/u/.bashrc"); got != Deny {
		t.Errorf("after DenyPath: %v", got)
	}
	if got := e.Eval("/home/u/.profile"); got != Ask {
		t.Errorf("DenyPath leaked to sibling: %v", got)
	}

	e.AllowFolderFor("/home/u/.m2", 20*time.Millisecond)
	if got := e.Eval("/home/u/.m2/x"); got != Allow {
		t.Errorf("timed grant: %v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if got := e.Eval("/home/u/.m2/x"); got != Ask {
		t.Errorf("expired grant: %v", got)
	}
	e.AllowFolderFor("/home/u/.npm", time.Millisecond) // session grant must not shrink
	time.Sleep(5 * time.Millisecond)
	if got := e.Eval("/home/u/.npm/x"); got != Allow {
		t.Errorf("session grant shortened: %v", got)
	}
}

func TestFolderFor(t *testing.T) {
	e := newTestEngine()
	for _, tc := range []struct{ path, want string }{
		{"/home/u/other/x/y/f", "/home/u/other"},
		{"/home/u/.cache/pip/ab/f", "/home/u/.cache/pip"},
		{"/home/u/.npm/f", "/home/u/.npm"},
		{"/home/u/.local/share/app/x/f", "/home/u/.local/share/app"},
		{"/opt/tool/lib/f", "/opt/tool"},
		{"/etc/f", "/etc"},
		{"/home/u/.bashrc", ""}, // would be $HOME
		{"/f", ""},
		{"/home/u/.ssh/f", "/home/u/.ssh"}, // the secret store itself may be offered as its own scope
		{"/home/u/.config/x", ""},          // ~/.config contains ~/.config/gh
		{"/home/u/.config/app/x", "/home/u/.config/app"},
	} {
		if got := e.FolderFor(tc.path); got != tc.want {
			t.Errorf("FolderFor(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestProcGrants(t *testing.T) {
	e := newTestEngine()
	k := ProcKey{Name: "oom_score_adj", Comm: "bash"}
	other := ProcKey{Name: "oom_score_adj", Comm: "sshd"}
	if got := e.EvalProc(k); got != Ask {
		t.Fatalf("initial: %v, want ask", got)
	}
	e.AllowProcFor(k, time.Millisecond)
	if got := e.EvalProc(k); got != Allow {
		t.Errorf("temp grant: %v, want allow", got)
	}
	time.Sleep(5 * time.Millisecond)
	if got := e.EvalProc(k); got != Ask {
		t.Errorf("expired grant: %v, want ask", got)
	}
	e.AllowProcFor(k, 0)
	e.AllowProcFor(k, time.Millisecond) // must not shrink the session grant
	time.Sleep(5 * time.Millisecond)
	if got := e.EvalProc(k); got != Allow {
		t.Errorf("session grant: %v, want allow", got)
	}
	e.DenyProc(other)
	if got := e.EvalProc(other); got != Deny {
		t.Errorf("never: %v, want deny", got)
	}
}

func TestRules(t *testing.T) {
	e := newTestEngine()
	e.DenyPath("/home/u/.bashrc")
	e.AllowFolderFor("/home/u/src", 0)
	e.AllowFolderFor("/home/u/.npm", time.Hour)
	has := func(want Rule) bool {
		for _, r := range e.Rules() {
			if r.Path == want.Path && r.Tree == want.Tree && r.Deny == want.Deny && r.Expires.IsZero() == want.Expires.IsZero() {
				return true
			}
		}
		return false
	}
	for _, want := range []Rule{
		{Path: "/home/u/src/proj", Tree: true},
		{Path: "/home/u/.cache/go-build", Tree: true},
		{Path: "/home/u/.bashrc", Deny: true},
		{Path: "/home/u/src", Tree: true},
		{Path: "/home/u/.npm", Tree: true, Expires: time.Now()},
	} {
		if !has(want) {
			t.Errorf("missing %+v in %+v", want, e.Rules())
		}
	}

	k := ProcKey{Name: "oom_score_adj", Comm: "node"}
	e.AllowProcFor(k, 0)
	e.DenyProc(ProcKey{Name: "mem", Comm: "node"})
	got := map[ProcKey]bool{}
	for _, r := range e.ProcRules() {
		got[r.ProcKey] = r.Deny
	}
	if deny, ok := got[k]; !ok || deny {
		t.Errorf("allowed proc rule: %v", got)
	}
	if deny, ok := got[ProcKey{Name: "mem", Comm: "node"}]; !ok || !deny {
		t.Errorf("denied proc rule: %v", got)
	}

	d := strings.Join(e.Describe(), "\n")
	for _, want := range []string{"  ~/.ssh (SSH keys)\n", "  ~/src/proj (project)\n", "  ~/.bashrc (this path only)\n", "  /dev/null\n", "  ~/tmp/hallpass-1 ($TMPDIR, removed at exit if empty)\n", "~/.npm (until ", "/proc/<pid>/mem of node processes\nWritable", "flagged as a secret store:\n"} {
		if !strings.Contains(d, want) {
			t.Errorf("Describe lacks %q:\n%s", want, d)
		}
	}
}
