// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"golang.org/x/sys/unix"
)

// varlinkHelper resolves a name through systemd-resolved's varlink
// socket, as glibc's nss-resolve does, then connects to an address: args
// are label, name and the address.
func varlinkHelper(args []string) int {
	if len(args) != 3 {
		fmt.Println("varlink: want label name addr")
		return 1
	}
	label, name, addr := args[0], args[1], args[2]
	c, err := net.Dial("unix", dnsnames.ResolveSocket)
	if err != nil {
		fmt.Printf("%s-resolve=%v\n", label, err)
	} else {
		fmt.Fprintf(c, `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":%q}}`+"\x00", name)
		reply, err := bufio.NewReader(c).ReadString(0)
		if err != nil {
			fmt.Printf("%s-resolve=%v\n", label, err)
		} else if !strings.Contains(reply, `"addresses"`) {
			fmt.Printf("%s-resolve=%q\n", label, reply)
		}
		c.Close()
	}
	d, err := net.DialTimeout("tcp", addr, 5*time.Second)
	switch {
	case err == nil:
		d.Close()
		fmt.Printf("%s=ok\n", label)
	case errors.Is(err, unix.EACCES):
		fmt.Printf("%s=denied\n", label)
	default:
		fmt.Printf("%s=%v\n", label, err)
	}
	return 0
}

// resolvedSocket makes sure something answers at systemd-resolved's
// varlink socket: resolved itself, or, as root on a host without it, a
// fake one answering "localhost" with 127.0.0.1, removed after the test.
func resolvedSocket(t *testing.T) {
	t.Helper()
	if c, err := net.Dial("unix", dnsnames.ResolveSocket); err == nil {
		c.Close()
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("no systemd-resolved, and not root to fake it")
	}
	dir := filepath.Dir(dnsnames.ResolveSocket)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Remove(dir) })
	}
	if _, err := os.Lstat(dnsnames.ResolveSocket); err == nil {
		t.Skipf("%s exists and does not answer", dnsnames.ResolveSocket)
	}
	l, err := net.Listen("unix", dnsnames.ResolveSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					msg, err := r.ReadString(0)
					if err != nil {
						return
					}
					reply := `{"error":"io.systemd.Resolve.NoSuchResourceRecord"}`
					if strings.Contains(msg, `"name":"localhost"`) {
						reply = `{"parameters":{"addresses":[{"ifindex":1,"family":2,"address":[127,0,0,1]}],"name":"localhost","flags":1}}`
					}
					fmt.Fprint(c, reply+"\x00")
				}
			}()
		}
	}()
}

// TestVarlinkNames: a program resolving through systemd-resolved's
// varlink socket (Fedora's glibc) gets prompts naming the address, from
// resolved's own answer, which hallpass relays. Denied the socket, it
// gets no name, and the relay is not made.
func TestVarlinkNames(t *testing.T) {
	needNames(t)
	resolvedSocket(t)
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			dest := l.Addr().String()
			l.Close()
			self, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range []struct {
				name, netFlag, wantName, wantResolve string
			}{
				{"allowed", "--allow-connect=unix:" + dnsnames.ResolveSocket, "localhost", ""},
				{"denied", "--deny-connect=unix:" + dnsnames.ResolveSocket, "", "d-resolve="},
			} {
				t.Run(c.name, func(t *testing.T) {
					e := newEnv(t)
					script := fmt.Sprintf(`HALLPASS_E2E_HELPER=varlink "$HP_SELF" d localhost %s`, dest)
					cmd := e.cmd(script, "--prompt=answer", "--timeout=20s", "--mediate=write,exec,connect", c.netFlag, "--mode="+mode)
					cmd.Env = append(cmd.Env, "HP_SELF="+self)
					var out strings.Builder
					cmd.Stdout, cmd.Stderr = &out, &out
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					p := dialPrompts(t, e, cmd)
					req, err := p.nextRequest(10 * time.Second)
					if err != nil {
						t.Fatalf("read prompt: %v\n%s", err, out.String())
					}
					pr := req.Prompt
					if pr.GetOp() != "connect to" || pr.GetPath() != dest || pr.GetHostNames() != c.wantName {
						t.Errorf("prompt %v, want connect to %s named %q", pr, dest, c.wantName)
					}
					p.answer(req.Id, "deny")
					if err := cmd.Wait(); err != nil {
						t.Fatalf("hallpass: %v\n%s", err, out.String())
					}
					o := out.String()
					if !strings.Contains(o, "d=denied\n") || (c.wantResolve == "") != !strings.Contains(o, "d-resolve=") ||
						(c.wantResolve != "" && !strings.Contains(o, c.wantResolve)) {
						t.Errorf("output:\n%s", o)
					}
				})
			}
		})
	}
}
