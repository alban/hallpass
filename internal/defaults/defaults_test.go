// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package defaults

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
)

func newTest() *Defaults {
	d := New("/home/u", "/home/u/src/proj", append(DefaultAllows(), "/home/u/.cache/go-build"), nil)
	d.SetTmpdir("/home/u/tmp/hallpass-1")
	return d
}

// eval is what the monitor decides on a write of path.
func eval(rs []rules.Rule, path string) string {
	v, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: path}}, time.Now())
	switch {
	case !ok || v == rules.Ask:
		return "ask"
	case v == rules.Allow:
		return "allow"
	}
	return "deny"
}

func TestRules(t *testing.T) {
	rs := newTest().Rules()
	for _, tc := range []struct{ path, want string }{
		{"/home/u/src/proj/main.go", "allow"},
		{"/home/u/src/proj", "allow"},
		{"/home/u/src/projX/main.go", "ask"}, // prefix match is per component
		{"/home/u/.cache/go-build/ab/x", "allow"},
		{"/tmp/x", "ask"},
		{"/dev/shm/x", "ask"},
		{"/home/u/tmp/hallpass-1/x", "allow"},
		{"/dev/null", "allow"},
		{"/dev/ptmx", "allow"},
		{"/dev/pts/3", "ask"}, // another session's terminal
		{"/home/u/.ssh/authorized_keys", "ask"},
		{"/home/u/.ssh", "ask"},
		{"/home/u/.bashrc", "ask"},
		{"/etc/passwd", "ask"},
	} {
		if got := eval(rs, tc.path); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.path, got, tc.want)
		}
	}
	for _, r := range rs {
		if r.Set != Set || r.Ops != rules.OpAll || !r.Object.Path.Tree {
			t.Errorf("rule %+v", r)
		}
	}
}

func TestWarn(t *testing.T) {
	d := newTest()
	for _, tc := range []struct{ path, want string }{
		{"/home/u/.ssh/authorized_keys", "SSH keys"},
		{"/home/u/.ssh", "SSH keys"},
		{"/home/u/.aws/credentials", "AWS credentials"},
		{"/home/u/.config/gh/hosts.yml", "GitHub CLI credentials"},
		{"/home/u/.sshx", ""},
		{"/home/u/.bashrc", ""},
		{"/home/u/src/proj/main.go", ""},
	} {
		if got := d.Warn(tc.path); got != tc.want {
			t.Errorf("Warn(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestAllowDevice(t *testing.T) {
	d := newTest()
	d.AllowDevice("/dev/pts/7")
	rs := d.Rules()
	if got := eval(rs, "/dev/pts/7"); got != "allow" {
		t.Errorf("own terminal: %s", got)
	}
	if got := eval(rs, "/dev/pts/8"); got != "ask" {
		t.Errorf("other terminal: %s", got)
	}
}

// TestLexical checks that container paths are not resolved against the
// caller's filesystem.
func TestLexical(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("/etc", link); err != nil {
		t.Fatal(err)
	}
	d := NewLexical("/root", "", []string{link + "/"}, []string{"/var/run/secrets"})
	rs := d.Rules()
	if got := eval(rs, link+"/f"); got != "allow" {
		t.Errorf("%s/f: %s, want allow", link, got)
	}
	if got := eval(rs, "/etc/f"); got != "ask" {
		t.Errorf("/etc/f: %s, want ask", got)
	}
	if got := eval(rs, "/var/run/secrets/token"); got != "deny" {
		t.Errorf("secret: %s, want deny", got)
	}
	if d.Warn("/root/.ssh/id") == "" {
		t.Errorf("/root/.ssh not flagged")
	}
}

func TestNoWorkdir(t *testing.T) {
	rs := New("/home/u", "", []string{"/home/u/out"}, nil).Rules()
	for _, tc := range []struct{ path, want string }{
		{"/home/u/src/proj/f", "ask"},
		{"/x", "ask"},
		{"/dev/null", "ask"},
		{"/home/u/out/f", "allow"},
	} {
		if got := eval(rs, tc.path); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.path, got, tc.want)
		}
	}
}

func TestDenyWinsOverWorkdir(t *testing.T) {
	rs := New("/home/u", "/home/u/secret", nil, []string{"/home/u/secret"}).Rules()
	if got := eval(rs, "/home/u/secret/config"); got != "deny" {
		t.Errorf("got %s, want deny", got)
	}
}

func TestFolderFor(t *testing.T) {
	d := newTest()
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
		if got := d.FolderFor(tc.path); got != tc.want {
			t.Errorf("FolderFor(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestDescribe(t *testing.T) {
	d := newTest()
	rs := append(d.Rules(),
		rules.Rule{Ops: rules.OpAll, Verdict: rules.Deny, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/home/u/.bashrc"}}},
		rules.Rule{Ops: rules.OpAll, Verdict: rules.Allow, Expires: time.Now().Add(time.Hour), Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/home/u/.npm", Tree: true}}},
		rules.Rule{Ops: rules.OpAll, Verdict: rules.Deny, Object: rules.ObjectMatch{Proc: &rules.ProcMatch{Name: "mem", Comm: "node"}}},
	)
	s := strings.Join(d.Describe(rs), "\n")
	for _, want := range []string{"  ~/.ssh (SSH keys)\n", "  ~/src/proj (project)\n", "  ~/.bashrc (this path only)\n", "  /dev/null\n", "  ~/tmp/hallpass-1 ($TMPDIR, removed at exit if empty)\n", "~/.npm (until ", "/proc/<pid>/mem of node processes\nWritable", "flagged as a secret store:\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("Describe lacks %q:\n%s", want, s)
		}
	}
}
