// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// dnsHelper sends a DNS query for a name to 127.0.0.1:53, as glibc does
// (a connected socket, then sendmmsg without an address) or as musl does
// (sendto with the address), then connects to an address: args are
// label, style ("connected" or "sendto"), name and the address.
func dnsHelper(args []string) int {
	if len(args) != 4 {
		fmt.Println("dns: want label style name addr")
		return 1
	}
	label, style, name, addr := args[0], args[1], args[2], args[3]
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	q, _ := b.Finish()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Println("dns:", err)
		return 1
	}
	defer unix.Close(fd)
	server := &unix.SockaddrInet4{Port: 53, Addr: [4]byte{127, 0, 0, 1}}
	switch style {
	case "connected":
		if err = unix.Connect(fd, server); err == nil {
			err = sendmmsg(fd, q)
		}
	case "sendto":
		err = unix.Sendto(fd, q, 0, server)
	}
	if err != nil {
		fmt.Printf("%s-query=%v\n", label, err)
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	switch {
	case err == nil:
		c.Close()
		fmt.Printf("%s=ok\n", label)
	case errors.Is(err, unix.EACCES):
		fmt.Printf("%s=denied\n", label)
	default:
		fmt.Printf("%s=%v\n", label, err)
	}
	return 0
}

// sendmmsg sends one message on connected socket fd with sendmmsg, without
// an address, as glibc's resolver sends its A and AAAA queries.
func sendmmsg(fd int, b []byte) error {
	var msgs [1]struct {
		hdr unix.Msghdr
		len uint32
		_   uint32
	}
	iov := unix.Iovec{Base: &b[0]}
	iov.SetLen(len(b))
	msgs[0].hdr.Iov = &iov
	msgs[0].hdr.SetIovlen(1)
	_, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), 1, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// TestDNSNames: a connect prompt names the address after the workload's
// DNS query for it, sent either way, once hallpass has looked the name up
// itself (localhost: 127.0.0.1 without any network). A query hallpass
// denies is not looked up: no name.
func TestDNSNames(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			// A port with no listener: the connect is refused, after
			// the prompt.
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
				name, style, netFlag, wantName string
			}{
				{"connected", "connected", "--allow-net=udp:127.0.0.1:53", "localhost"},
				{"sendto", "sendto", "--allow-net=udp:127.0.0.1:53", "localhost"},
				{"denied", "sendto", "--deny-net=udp:127.0.0.1:53", ""},
			} {
				t.Run(c.name, func(t *testing.T) {
					e := newEnv(t)
					script := fmt.Sprintf(`HALLPASS_E2E_HELPER=dns "$HP_SELF" d %s localhost %s`, c.style, dest)
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
					if pr.GetOp() != "connect to" || pr.GetPath() != dest || pr.GetHostNames() != c.wantName || pr.GetScope() != dest {
						t.Errorf("prompt %v, want connect to %s named %q, scope the address", pr, dest, c.wantName)
					}
					p.answer(req.Id, "deny")
					if err := cmd.Wait(); err != nil {
						t.Fatalf("hallpass: %v\n%s", err, out.String())
					}
					if !strings.Contains(out.String(), "d=denied\n") {
						t.Errorf("output:\n%s", out.String())
					}
				})
			}
		})
	}
}
