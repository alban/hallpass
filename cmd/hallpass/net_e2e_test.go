// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/alban/hallpass/internal/lsm"
	"golang.org/x/sys/unix"
)

// modes returns the modes to test: lite, and strict when it can run.
func modes(t *testing.T) []string {
	m := []string{"lite"}
	if os.Geteuid() == 0 && lsm.Active() == nil {
		m = append(m, "strict")
	} else if os.Getenv("HALLPASS_REQUIRE_LSM") == "1" {
		t.Fatal("HALLPASS_REQUIRE_LSM=1: strict mode cannot run")
	}
	return m
}

// TestMediateExec checks that --mediate without files leaves writes alone,
// in the filter and, in strict mode, in the kernel.
func TestMediateExec(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			c := e.cmd(`echo x > "$HOME/outside" && echo write=ok`, "--mode="+mode, "--ask=deny", "--mediate=exec")
			out, err := c.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "write=ok") {
				t.Errorf("%v\n%s", err, out)
			}
		})
	}
}

func TestMediateBad(t *testing.T) {
	e := newEnv(t)
	out, err := e.cmd("true", "--mediate=files,dns").CombinedOutput()
	if err == nil || !strings.Contains(string(out), `unknown category "dns"`) {
		t.Errorf("%v\n%s", err, out)
	}
}

// netHelper connects or sends to an address with raw syscalls and prints
// label=ok, label=denied (EACCES) or label=error. Args: label, connect,
// sendto or sendmsg, and an address: ADDR:PORT, /path or @abstract.
func netHelper(args []string) int {
	if len(args) != 3 {
		fmt.Println("net: want label kind addr")
		return 1
	}
	var err error
	if k, ok := strings.CutPrefix(args[1], "inside-"); ok {
		err = netInside(k, args[2])
	} else {
		err = netTry(args[1], args[2])
	}
	switch {
	case err == nil:
		fmt.Printf("%s=ok\n", args[0])
	case errors.Is(err, unix.EACCES):
		fmt.Printf("%s=denied\n", args[0])
	default:
		fmt.Printf("%s=%v\n", args[0], err)
	}
	return 0
}

// netInside listens on addr (a listener started inside the sandbox), then
// tries kind on it: connect for tcp ("127.0.0.1:0", "[::]:0": a wildcard
// reached through 127.0.0.1) and unix paths or abstract names, sendto for
// unixgram.
func netInside(kind, addr string) error {
	switch kind {
	case "tcp":
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		defer l.Close()
		port := l.Addr().(*net.TCPAddr).Port
		return netTry("connect", fmt.Sprintf("127.0.0.1:%d", port))
	case "unix":
		l, err := net.Listen("unix", addr)
		if err != nil {
			return err
		}
		defer l.Close()
		return netTry("connect", addr)
	case "unixgram":
		l, err := net.ListenPacket("unixgram", addr)
		if err != nil {
			return err
		}
		defer l.Close()
		return netTry("sendto", addr)
	}
	return fmt.Errorf("unknown kind %s", kind)
}

func netTry(kind, addr string) error {
	var sa unix.Sockaddr
	domain := unix.AF_UNIX
	if addr[0] == '/' || addr[0] == '@' {
		sa = &unix.SockaddrUnix{Name: addr}
	} else {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return err
		}
		if ap.Addr().Is4() {
			domain = unix.AF_INET
			sa = &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}
		} else {
			domain = unix.AF_INET6
			sa = &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
		}
	}
	typ := unix.SOCK_DGRAM
	if kind == "connect" {
		typ = unix.SOCK_STREAM
	}
	fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	switch kind {
	case "connect":
		return unix.Connect(fd, sa)
	case "sendto":
		return unix.Sendto(fd, []byte("x"), 0, sa)
	case "sendmsg":
		_, err := unix.SendmsgN(fd, []byte("x"), nil, sa, 0)
		return err
	case "unspec":
		// udp_sendmsg reads an AF_UNSPEC address as AF_INET.
		in, ok := sa.(*unix.SockaddrInet4)
		if !ok {
			return fmt.Errorf("unspec: want an IPv4 address")
		}
		raw := unix.RawSockaddrInet4{Family: unix.AF_UNSPEC, Addr: in.Addr}
		binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&raw.Port))[:], uint16(in.Port))
		b := []byte("x")
		_, _, e := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), 1, 0,
			uintptr(unsafe.Pointer(&raw)), unix.SizeofSockaddrInet4)
		if e != 0 {
			return e
		}
		return nil
	}
	return fmt.Errorf("unknown kind %s", kind)
}

// netTargets are listeners outside the sandbox: TCP and UDP on loopback,
// unix stream and datagram sockets, and an abstract one.
type netTargets struct {
	tcp, udp, unix, unixgram, abstract string
	accepted                           atomic.Int32
}

func listenOutside(t *testing.T, dir string) *netTargets {
	t.Helper()
	nt := &netTargets{unix: dir + "/s.sock", unixgram: dir + "/d.sock", abstract: fmt.Sprintf("@hallpass-e2e-%d-%s", os.Getpid(), t.Name())}
	var ls []net.Listener
	for _, a := range [][2]string{{"tcp", "127.0.0.1:0"}, {"unix", nt.unix}, {"unix", nt.abstract}} {
		l, err := net.Listen(a[0], a[1])
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				nt.accepted.Add(1)
				c.Close()
			}
		}()
	}
	nt.tcp = ls[0].Addr().String()
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nt.udp = u.LocalAddr().String()
	g, err := net.ListenPacket("unixgram", nt.unixgram)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, l := range ls {
			l.Close()
		}
		u.Close()
		g.Close()
	})
	return nt
}

// script tries every target, printing label=ok|denied|error lines.
func (nt *netTargets) script() string {
	_, port, _ := net.SplitHostPort(nt.tcp)
	return fmt.Sprintf(`
H() { HALLPASS_E2E_HELPER=net "$HP_SELF" "$@"; }
H tcp connect %s
H mapped connect '[::ffff:127.0.0.1]:%s'
H udpto sendto %s
H udpmsg sendmsg %s
H udpunspec unspec %s
H unix connect %s
H unixgram sendto %s
H abstract connect %s
`, nt.tcp, port, nt.udp, nt.udp, nt.udp, nt.unix, nt.unixgram, nt.abstract)
}

var netLabels = []string{"tcp", "mapped", "udpto", "udpmsg", "udpunspec", "unix", "unixgram", "abstract"}

func (e env) netCmd(t *testing.T, nt *netTargets, flags ...string) map[string]string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := e.cmd(nt.script(), flags...)
	c.Env = append(c.Env, "HP_SELF="+self)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	t.Logf("output:\n%s", out)
	return got
}

// TestNetLite checks the outcome of connections and sends to listeners
// outside the sandbox, with network mediated or not.
func TestNetLite(t *testing.T) {
	for _, mode := range modes(t) {
		for _, tc := range []struct {
			name  string
			flags []string
			want  string
		}{
			{"not mediated", []string{"--ask=deny"}, "ok"},
			{"deny", []string{"--ask=deny", "--mediate=files,exec,network"}, "denied"},
			{"audit", []string{"--ask=allow", "--mediate=files,exec,network"}, "ok"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				e := newEnv(t)
				nt := listenOutside(t, e.root)
				got := e.netCmd(t, nt, append(tc.flags, "--mode="+mode)...)
				for _, l := range netLabels {
					if got[l] != tc.want {
						t.Errorf("%s: %q, want %q", l, got[l], tc.want)
					}
				}
				want := int32(0)
				if tc.want == "ok" {
					want = 4 // tcp, mapped, unix, abstract
				}
				for i := 0; i < 50 && nt.accepted.Load() != want; i++ {
					time.Sleep(10 * time.Millisecond)
				}
				if n := nt.accepted.Load(); n != want {
					t.Errorf("%d connections accepted, want %d", n, want)
				}
			})
		}
	}
}

// TestNetInside: listeners started inside the sandbox are reached without
// asking, but for --no-implicit.
func TestNetInside(t *testing.T) {
	for _, mode := range modes(t) {
		for _, tc := range []struct {
			name  string
			flags []string
			want  string
		}{
			{"implicit", []string{"--ask=deny", "--mediate=files,exec,network"}, "ok"},
			{"no-implicit", []string{"--ask=deny", "--mediate=files,exec,network", "--no-implicit", "--allow=" + "/"}, "denied"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				e := newEnv(t)
				self, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				abstract := fmt.Sprintf("@hallpass-e2e-in-%d-%s", os.Getpid(), t.Name())
				script := fmt.Sprintf(`
H() { HALLPASS_E2E_HELPER=net "$HP_SELF" "$@"; }
H tcp inside-tcp 127.0.0.1:0
H wildcard inside-tcp '[::]:0'
H unix inside-unix %s/in.sock
H unixgram inside-unixgram %s/in-d.sock
H abstract inside-unix %s
`, e.root, e.root, abstract)
				c := e.cmd(script, append(tc.flags, "--mode="+mode)...)
				c.Env = append(c.Env, "HP_SELF="+self)
				out, err := c.CombinedOutput()
				if err != nil {
					t.Fatalf("%v\n%s", err, out)
				}
				t.Logf("output:\n%s", out)
				for _, l := range []string{"tcp", "wildcard", "unix", "unixgram", "abstract"} {
					if !strings.Contains(string(out), l+"="+tc.want+"\n") {
						t.Errorf("%s: want %s", l, tc.want)
					}
				}
			})
		}
	}
}
