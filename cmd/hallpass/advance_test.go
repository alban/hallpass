// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/lsm"
)

// advanceScript defines adv: `adv NAME QUERY` asks /proc/self/hallpass/
// QUERY the way the docs show, with a shell's exec, and prints
// "NAME=STRERROR rc=CODE".
const advanceScript = `
adv() { m=$(sh -c "exec '/proc/self/hallpass/$2'" 2>&1); echo "$1=${m##*: } rc=$?"; }
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
`

// advanceWant is the line adv prints for errno, lower case: glibc's
// strerror capitalises, Go's does not.
func advanceWant(name string, errno unix.Errno) string {
	return strings.ToLower(name + "=" + errno.Error() + " rc=126")
}

func advanceModes(t *testing.T, f func(t *testing.T, mode string)) {
	for _, mode := range []string{"lite", "strict"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "strict" {
				if os.Geteuid() != 0 {
					strictSkip(t, "needs root (go test -exec sudo)")
				}
				if err := lsm.Active(); err != nil {
					strictSkip(t, err.Error())
				}
			}
			f(t, mode)
		})
	}
}

// TestAdvance asks for a folder in advance, is granted it, then writes
// there without being asked; strict mode's kernel enforces the grant.
func TestAdvance(t *testing.T) {
	advanceModes(t, func(t *testing.T, mode string) {
		e := newEnv(t)
		tree := "op=write&path=" + e.home + "/adv/**&for=10m&reason=build+cache%0a%1b[2J"
		script := advanceScript + `
adv check1 'check?` + tree + `'
adv grant 'request?` + tree + `'
check write sh -c 'mkdir "$HOME/adv" "$HOME/adv/sub" && echo x > "$HOME/adv/sub/f"'
adv again 'request?` + tree + `'
adv check2 'check?` + tree + `'
adv longer 'check?op=write&path=` + e.home + `/adv/**&for=1h'
adv deny 'request?op=write&path=` + e.home + `/no'
adv bad 'request?op=read&path=/x'
adv relative 'request?op=write&path=x'
adv long "request?op=write&path=/$(printf %5000s | tr ' ' a)"
`
		c := e.cmd(script, "--mode="+mode, "--ask=answer", "--timeout=20s")
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
		if a := r.GetAdvance(); !a.GetTree() || a.GetFor().AsDuration() != 10*time.Minute || a.GetReason() != "build cache\n\x1b[2J" {
			t.Errorf("advance %v", a)
		}
		if !pr.GetAdvance() || pr.GetPath() != e.home+"/adv/**" || pr.GetOp() != "write" || pr.GetGrantFor().AsDuration() != 10*time.Minute {
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
		for _, want := range []string{
			advanceWant("check1", unix.ENOMSG),
			advanceWant("grant", unix.EALREADY),
			"write=ok",
			advanceWant("again", unix.EEXIST),
			advanceWant("check2", unix.EEXIST),
			advanceWant("longer", unix.ENOMSG),
			advanceWant("deny", unix.EPERM),
			advanceWant("bad", unix.EINVAL),
			advanceWant("relative", unix.EINVAL),
		} {
			if !strings.Contains(strings.ToLower(out.String()), want+"\n") {
				t.Errorf("output lacks %q", want)
			}
		}
		// dash exits 127 for it, bash 126.
		if want := strings.ToLower("long=" + unix.ENAMETOOLONG.Error() + " rc=12"); !strings.Contains(strings.ToLower(out.String()), want) {
			t.Errorf("output lacks %q", want)
		}
		if b, err := os.ReadFile(e.home + "/adv/sub/f"); err != nil || string(b) != "x\n" {
			t.Errorf("adv/sub/f: %q, %v", b, err)
		}
		if t.Failed() {
			t.Logf("output:\n%s", out.String())
		}
	})
}

// TestAdvanceNoAnswer: --ask=deny denies requests made in advance at once,
// a prompt nobody answers times out, and without hallpass the path does
// not exist.
func TestAdvanceNoAnswer(t *testing.T) {
	advanceModes(t, func(t *testing.T, mode string) {
		e := newEnv(t)
		q := "request?op=write&path=" + e.home + "/x"
		script := advanceScript + "adv req '" + q + "'\nadv bad 'request?op=read&path=/x'\n"
		for _, tc := range []struct {
			flags []string
			want  string
		}{
			{[]string{"--ask=deny"}, advanceWant("req", unix.EPERM)},
			{[]string{"--ask=answer", "--timeout=1s"}, advanceWant("req", unix.ETIMEDOUT)},
			{[]string{"--ask=allow"}, advanceWant("req", unix.EALREADY)},
			// execve is notified whatever the categories mediated.
			{[]string{"--ask=deny", "--mediate=exec"}, advanceWant("req", unix.EPERM)},
		} {
			c := e.cmd(script, append([]string{"--mode=" + mode}, tc.flags...)...)
			out, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %v\n%s", tc.flags, err, out)
			}
			for _, want := range []string{tc.want, advanceWant("bad", unix.EINVAL)} {
				if !strings.Contains(strings.ToLower(string(out)), want+"\n") {
					t.Errorf("%v: output lacks %q:\n%s", tc.flags, want, out)
				}
			}
		}
	})
	out, _ := exec.Command("/bin/sh", "-c", "exec '/proc/self/hallpass/request?op=write&path=/x'; echo unreachable").CombinedOutput()
	if strings.Contains(string(out), "unreachable") {
		t.Errorf("exec without hallpass: %s", out)
	}
	c := exec.Command("/bin/sh", "-c", "exec '/proc/self/hallpass/request?op=write&path=/x'")
	if err := c.Run(); err == nil || c.ProcessState.ExitCode() != 127 {
		t.Errorf("exec without hallpass: %v, want exit 127", err)
	}
}
