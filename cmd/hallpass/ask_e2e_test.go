// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/rules"
)

// askTree returns the rule asking about the tree at path, or allowing it.
func askTree(path string, v pb.RuleVerdict) *pb.Rule {
	return &pb.Rule{Ops: uint32(rules.OpAll), Verdict: v, Object: &pb.ObjectMatch{Kind: &pb.ObjectMatch_Path{Path: &pb.PathMatch{Path: path, Tree: true}}}}
}

// TestAskRules checks ask rules inside what is allowed, in both modes: a
// sub-tree of the project, an address of an allowed prefix, an abstract
// name of an allowed pattern. They are asked about, "once" allows them,
// and a more specific allow under them is not asked about.
func TestAskRules(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			nt := listenOutside(t, e.root)
			if err := os.MkdirAll(e.proj+"/secret/ok", 0o700); err != nil {
				t.Fatal(err)
			}
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			script := fmt.Sprintf(`
H() { HALLPASS_E2E_HELPER=net "$HP_SELF" "$@"; }
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
while [ ! -e go ]; do sleep 0.05; done
check once    sh -c 'echo x > secret/a'
check again   sh -c 'echo x > secret/a'
check deeper  sh -c 'echo x > secret/ok/f'
check outside sh -c 'echo x > other'
H tonce connect %[1]s
H tagain connect %[1]s
H udp sendto %[2]s
H aonce connect %[3]s
`, nt.tcp, nt.udp, nt.abstract)
			c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s", "--mediate=write,exec,connect",
				"--allow-net=127.0.0.0/8", "--ask-net=127.0.0.1", "--allow-net=udp:"+nt.udp,
				"--allow-net=unix:@hallpass-e2e-*", "--ask-net=unix:"+nt.abstract)
			c.Env = append(c.Env, "HP_SELF="+self)
			var out strings.Builder
			c.Stdout, c.Stderr = &out, &out
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			p := dialPrompts(t, e, c)
			if _, err := p.c.Apply(context.Background(), &pb.Decision{Client: "test", AddRules: []*pb.Rule{
				askTree(e.proj+"/secret", pb.RuleVerdict_ASK),
				askTree(e.proj+"/secret/ok", pb.RuleVerdict_ALLOW),
			}}); err != nil {
				c.Process.Kill()
				t.Fatal(err)
			}
			if err := os.WriteFile(e.proj+"/go", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			for _, st := range []struct{ path, reply string }{
				{e.proj + "/secret/a", "once"},
				{e.proj + "/secret/a", "deny"},
				{nt.tcp, "once"},
				{nt.tcp, "deny"},
				{"unix " + nt.abstract, "once"},
			} {
				id, path, err := p.next(10 * time.Second)
				if err != nil || path != st.path {
					c.Process.Kill()
					c.Wait()
					t.Fatalf("prompt %q, want %q: %v\n%s", path, st.path, err, out.String())
				}
				p.answer(id, st.reply)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out.String())
			}
			for _, want := range []string{"once=ok", "again=denied", "deeper=ok", "outside=ok", "tonce=ok", "tagain=denied", "udp=ok", "aonce=ok"} {
				if !strings.Contains(out.String(), want+"\n") {
					t.Errorf("output lacks %q", want)
				}
			}
			if t.Failed() {
				t.Logf("output:\n%s", out.String())
			}
		})
	}
}

// TestAskPath checks --ask-path in both modes: a write in the allowed
// tree is not asked about, one in the asked sub-tree is ("once" allows
// it), and a more specific --allow-path under it is not.
func TestAskPath(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			dir := e.home + "/data"
			if err := os.MkdirAll(dir+"/sub/ok", 0o700); err != nil {
				t.Fatal(err)
			}
			script := fmt.Sprintf(`
check() { name=$1; shift; if "$@" 2>/dev/null; then echo "$name=ok"; else echo "$name=denied"; fi; }
cd %q
check allowed sh -c 'echo x > a'
check once    sh -c 'echo x > sub/b'
check again   sh -c 'echo x > sub/b'
check deeper  sh -c 'echo x > sub/ok/c'
`, dir)
			c := e.cmd(script, "--mode="+mode, "--prompt=answer", "--timeout=20s",
				"--allow-path="+dir, "--ask-path="+dir+"/sub", "--allow-path="+dir+"/sub/ok")
			var out strings.Builder
			c.Stdout, c.Stderr = &out, &out
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			p := dialPrompts(t, e, c)
			for _, reply := range []string{"once", "deny"} {
				id, path, err := p.next(10 * time.Second)
				if err != nil || path != dir+"/sub/b" {
					c.Process.Kill()
					c.Wait()
					t.Fatalf("prompt %q, want %q: %v\n%s", path, dir+"/sub/b", err, out.String())
				}
				p.answer(id, reply)
			}
			if err := c.Wait(); err != nil {
				t.Fatalf("hallpass: %v\n%s", err, out.String())
			}
			for _, want := range []string{"allowed=ok", "once=ok", "again=denied", "deeper=ok"} {
				if !strings.Contains(out.String(), want+"\n") {
					t.Errorf("output lacks %q", want)
				}
			}
			if t.Failed() {
				t.Logf("output:\n%s", out.String())
			}
		})
	}
}

// TestAskTOCTOU swaps the path hallpass asks about for a file under an ask
// rule, inside the allowed project: strict mode denies the open, as the
// ask rule stops the project's allow in the kernel and "once" covers the
// file asked about only. Lite mode opens it: see checkTOCTOU.
func TestAskTOCTOU(t *testing.T) {
	toctouModes(t, func(t *testing.T, e env, mode string) {
		asked, secret := e.home+"/asked", e.proj+"/secret/f"
		if err := os.MkdirAll(e.proj+"/secret", 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{asked, secret} {
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := toctou(t, e, mode, asked, func(p prompter, pid uint32) error {
			if _, err := p.c.Apply(context.Background(), &pb.Decision{Client: "test", AddRules: []*pb.Rule{askTree(e.proj+"/secret", pb.RuleVerdict_ASK)}}); err != nil {
				return err
			}
			return swapPath(pid, secret)
		})
		want, wantSecret := "open=EACCES", ""
		if mode == "lite" {
			want, wantSecret = "open=ok", "toctou\n"
		}
		if !strings.Contains(out, want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
		if b, _ := os.ReadFile(secret); string(b) != wantSecret {
			t.Errorf("%s: %q, want %q", secret, b, wantSecret)
		}
	})
}
