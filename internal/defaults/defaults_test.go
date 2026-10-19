// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package defaults

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/programs"
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
	for _, want := range []string{"  ~/.ssh (SSH keys)\n", "  ~/src/proj (project)\n", "  ~/.bashrc (this path only)\n", "  /dev/null\n", "  ~/tmp/hallpass-1 ($TMPDIR, removed at exit if empty)\n", "~/.npm (until ", "/proc/<pid>/mem of node processes\nAllowed", "flagged as a secret store:\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("Describe lacks %q:\n%s", want, s)
		}
	}
}

func TestNet(t *testing.T) {
	d := newTest()
	all, _ := rules.ParseNet("all")
	ssh, _ := rules.ParseNet("tcp:10.0.0.0/8:22")
	box, _ := rules.ParseNet("10.0.0.1")
	d.AllowNet(all)
	d.DenyNet(ssh)
	d.AskNet(box)
	rs := d.Rules()
	at := time.Now()
	for _, tc := range []struct {
		addr string
		want rules.Verdict
	}{{"10.1.2.3:22", rules.Deny}, {"10.1.2.3:80", rules.Allow}, {"[::1]:22", rules.Allow}, {"10.0.0.1:80", rules.Ask}, {"10.0.0.1:22", rules.Deny}} {
		obj := rules.Object{Inet: &rules.InetObject{Proto: 6, Addr: netip.MustParseAddrPort(tc.addr)}}
		if v, _, ok := rules.Eval(rs, rules.OpConnect, obj, at); !ok || v != tc.want {
			t.Errorf("%s: %v %v, want %v", tc.addr, v, ok, tc.want)
		}
	}
	if v, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: "/etc/x"}}, at); ok && v == rules.Allow {
		t.Error("allow-net all allows files")
	}
	s := strings.Join(d.Describe(rs), "\n")
	if !strings.Contains(s, "network: tcp:10.0.0.0/8:22\nAllowed") || !strings.Contains(s, "network: all\n") ||
		!strings.Contains(s, "Asked, even inside what is allowed:\n  network: 10.0.0.1\n") {
		t.Errorf("Describe:\n%s", s)
	}
}

func TestExecRules(t *testing.T) {
	d := NewLexical("/home/u", "/home/u/proj", nil, nil)
	d.AllowExec("/usr/bin/ls", false)
	d.AllowExec("/opt/tools", true)
	d.DenyExec("/opt/tools/bad", false)
	rs := d.Rules()
	at := time.Now()
	for path, want := range map[string]rules.Verdict{
		"/usr/bin/ls": rules.Allow, "/opt/tools/x/y": rules.Allow, "/opt/tools/bad": rules.Deny,
	} {
		if v, _, ok := rules.Eval(rs, rules.OpExec, rules.Object{Path: &rules.PathObject{Path: path}}, at); !ok || v != want {
			t.Errorf("exec %s: %v %v, want %v", path, v, ok, want)
		}
	}
	// The workdir is writable, not executable.
	if _, _, ok := rules.Eval(rs, rules.OpExec, rules.Object{Path: &rules.PathObject{Path: "/home/u/proj/run"}}, at); ok {
		t.Error("exec in the workdir matched a rule")
	}
	s := strings.Join(d.Describe(rs), "\n")
	if !strings.Contains(s, "Programs run without asking:\n  /usr/bin/ls\n  /opt/tools (and every program below)\n") || !strings.Contains(s, "  exec: /opt/tools/bad\n") {
		t.Errorf("Describe:\n%s", s)
	}

	// A group: its programs are allowed, the summary names it with its
	// count; a program already allowed (the command) stays listed.
	d.AllowExec("/usr/bin/cmd", false)
	d.SetGroups([]programs.Group{
		{Name: "@coreutils", Members: []string{"/usr/bin/cat", "/usr/bin/cmd", "/usr/bin/cp", "/usr/bin/ls"}},
		{Name: "@search", Members: []string{"/usr/bin/grep", "/usr/bin/cat"}},
	})
	d.AllowGroup("@coreutils")
	d.AllowGroup("@coreutils")
	d.AllowGroup("@nope")
	rs = d.Rules()
	_, _, _, run := d.Summary(rs)
	if want := []string{"/usr/bin/ls", "/opt/tools (and every program below)", "/usr/bin/cmd", "@coreutils (cat, cmd, cp, … 4 programs)"}; !slices.Equal(run, want) {
		t.Errorf("summary: %q, want %q", run, want)
	}
	n := 0
	for _, r := range rs {
		if r.Label == "@coreutils" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d @coreutils rules, want 2 (cat, cp)", n)
	}
	if v, _, ok := rules.Eval(rs, rules.OpExec, rules.Object{Path: &rules.PathObject{Path: "/usr/bin/cp"}}, at); !ok || v != rules.Allow {
		t.Errorf("cp: %v %v", v, ok)
	}
	if g, ok := d.Group("/usr/bin/cat"); !ok || g.Name != "@coreutils" {
		t.Errorf("Group(cat) = %v, %v", g, ok)
	}
	if g, ok := d.Group("/usr/bin/grep"); !ok || g.Name != "@search" {
		t.Errorf("Group(grep) = %v, %v", g, ok)
	}
	if _, ok := d.Group("/usr/bin/other"); ok {
		t.Error("Group(other)")
	}
}
