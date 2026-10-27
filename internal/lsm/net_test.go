// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// netHelperEnv makes the test binary run netHelper instead of the tests.
const netHelperEnv = "HALLPASS_LSM_NET_HELPER"

func init() {
	// Network operations run on the main thread, the one made a member.
	runtime.LockOSThread()
}

func TestMain(m *testing.M) {
	if os.Getenv(netHelperEnv) == "1" {
		netHelper(os.Args[1:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// netHelper waits for a line on stdin, then runs each op and prints "ok"
// or "fail: <error>" for each. Ops: "<kind> <dest>", with kind one of
// connect (TCP), connect6 (TCP over IPv6), sendto, sendmsg, unspec (UDP),
// fastopen (TCP), unix, unixgram, unixconn (connected datagram), own
// (TCP listener of the helper), ownunix (unix listener of the helper).
func netHelper(ops []string) {
	bufio.NewReader(os.Stdin).ReadString('\n')
	for _, op := range ops {
		kind, dest, _ := strings.Cut(op, " ")
		if err := netOp(kind, dest); err != nil {
			fmt.Println("fail:", err)
		} else {
			fmt.Println("ok")
		}
	}
}

func inet4(dest string) (*unix.SockaddrInet4, error) {
	ap, err := netip.ParseAddrPort(dest)
	if err != nil {
		return nil, err
	}
	return &unix.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().Unmap().As4()}, nil
}

func unixAddr(dest string) *unix.SockaddrUnix {
	if strings.HasPrefix(dest, "@") {
		return &unix.SockaddrUnix{Name: "\x00" + dest[1:]}
	}
	return &unix.SockaddrUnix{Name: dest}
}

func netOp(kind, dest string) error {
	switch kind {
	case "connect", "fastopen":
		sa, err := inet4(dest)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		if kind == "fastopen" {
			return unix.Sendto(fd, []byte("x"), unix.MSG_FASTOPEN, sa)
		}
		return unix.Connect(fd, sa)
	case "connect6":
		ap, err := netip.ParseAddrPort(dest)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Connect(fd, &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()})
	case "sendto", "sendmsg", "unspec":
		sa, err := inet4(dest)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		switch kind {
		case "sendmsg":
			return unix.Sendmsg(fd, []byte("x"), nil, sa, 0)
		case "unspec":
			// struct sockaddr_in with sin_family AF_UNSPEC: UDP takes it
			// as AF_INET.
			var raw unix.RawSockaddrInet4
			raw.Port = uint16(sa.Port>>8) | uint16(sa.Port&0xff)<<8
			raw.Addr = sa.Addr
			return rawSendto(fd, &raw)
		}
		return unix.Sendto(fd, []byte("x"), 0, sa)
	case "unix", "unixgram", "unixconn":
		typ := unix.SOCK_STREAM
		if kind != "unix" {
			typ = unix.SOCK_DGRAM
		}
		fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		switch kind {
		case "unixgram":
			return unix.Sendto(fd, []byte("x"), 0, unixAddr(dest))
		case "unixconn":
			if err := unix.Connect(fd, unixAddr(dest)); err != nil {
				return err
			}
			_, err := unix.Write(fd, []byte("x"))
			return err
		}
		return unix.Connect(fd, unixAddr(dest))
	case "own":
		ln, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(ln)
		if err := unix.Bind(ln, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return err
		}
		if err := unix.Listen(ln, 1); err != nil {
			return err
		}
		sa, err := unix.Getsockname(ln)
		if err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Connect(fd, sa)
	case "ownunix":
		ln, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(ln)
		if err := unix.Bind(ln, unixAddr(dest)); err != nil {
			return err
		}
		if err := unix.Listen(ln, 1); err != nil {
			return err
		}
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		return unix.Connect(fd, unixAddr(dest))
	}
	return fmt.Errorf("unknown op %q", kind)
}

// rawSendto sends one byte to raw, whatever its family.
func rawSendto(fd int, raw *unix.RawSockaddrInet4) error {
	b := []byte("x")
	_, _, e := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd), uintptr(unsafe.Pointer(&b[0])), 1, 0,
		uintptr(unsafe.Pointer(raw)), unix.SizeofSockaddrInet4)
	if e != 0 {
		return e
	}
	return nil
}

// netMember runs the helper with ops as a member of s, and returns its
// results, one per op.
func netMember(t *testing.T, s *Session, ops ...string) []string {
	t.Helper()
	cmd := exec.Command(os.Args[0], ops...)
	cmd.Env = append(os.Environ(), netHelperEnv+"=1")
	stdin, _ := cmd.StdinPipe()
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddMember(cmd.Process.Pid); err != nil {
		cmd.Process.Kill()
		t.Fatal(err)
	}
	stdin.Write([]byte("go\n"))
	stdin.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v\n%s", err, out.String())
	}
	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(got) != len(ops) {
		t.Fatalf("helper: %d results for %d ops:\n%s", len(got), len(ops), out.String())
	}
	return got
}

// TestEnforceNet checks the network rules of a session mediating the
// network, against listeners of the test, outside the session: without a
// grant, only unix sockets bound to a path may be allowed.
func TestEnforceNet(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	dir := t.TempDir()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	listen := func(netw, addr string) {
		var c io.Closer
		var err error
		if netw == "unixgram" {
			c, err = net.ListenPacket(netw, addr)
		} else {
			c, err = net.Listen(netw, addr)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
	}
	for _, d := range []string{"ok", "no", "own"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o777); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"ok", "no"} {
		listen("unix", filepath.Join(dir, d, "s"))
		listen("unixgram", filepath.Join(dir, d, "g"))
	}
	abs := fmt.Sprintf("@hallpass-test-%d", os.Getpid())
	listen("unix", abs)

	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s, off, all := newSession(t, l), newSession(t, l), newSession(t, l)
	for _, x := range []*Session{s, off, all} {
		if err := x.Mediate(true, false, x != off); err != nil {
			t.Fatal(err)
		}
		own := Rule{Path: dir + "/own", Tree: true}
		if err := x.Sync([]Rule{devNull, own, {Path: dir + "/ok", Tree: true, Net: true}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SyncUnix(UnixRules{OwnListeners: true}); err != nil {
		t.Fatal(err)
	}
	if err := all.SyncUnix(UnixRules{AnyUnix: []UnixAnyRule{{}}}); err != nil {
		t.Fatal(err)
	}
	go s.Events(func(e Event) { t.Logf("event: %+v %+v %+v", e, e.Inet, e.Unix) })

	tcp, udpAddr := ln.Addr().String(), udp.LocalAddr().String()
	cases := []struct {
		op    string
		ok    bool // in s
		allOK bool // in all
	}{
		{"connect " + tcp, false, false},
		{"connect6 [::ffff:127.0.0.1]:" + strings.TrimPrefix(tcp, "127.0.0.1:"), false, false},
		{"fastopen " + tcp, false, false},
		{"sendto " + udpAddr, false, false},
		{"sendmsg " + udpAddr, false, false},
		{"unspec " + udpAddr, false, false},
		{"own ", false, false},
		{"ownunix " + abs + "-own", false, false},
		{"ownunix " + dir + "/own/s", true, true},
		{"unix " + dir + "/ok/s", true, true},
		{"unix " + dir + "/no/s", false, true},
		{"unixgram " + dir + "/ok/g", true, true},
		{"unixgram " + dir + "/no/g", false, true},
		{"unixconn " + dir + "/ok/g", true, true},
		{"unixconn " + dir + "/no/g", false, true},
		{"unix " + abs, false, false},
	}
	var ops []string
	for _, c := range cases {
		ops = append(ops, c.op)
	}
	for _, x := range []struct {
		name string
		s    *Session
	}{{"mediated", s}, {"off", off}, {"all", all}} {
		os.Remove(dir + "/own/s")
		got := netMember(t, x.s, ops...)
		for i, c := range cases {
			want := x.s == off || x.s == s && c.ok || x.s == all && c.allOK
			if (got[i] == "ok") != want {
				t.Errorf("%s: %s: %s, want ok=%v", x.name, c.op, got[i], want)
			}
		}
	}
	time.Sleep(100 * time.Millisecond) // let the events be logged
}

// TestEnforceNetAsk checks ask rules on socket files: they stop the allows
// of less specific rules, a more specific allow wins over them.
func TestEnforceNetAsk(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	dir := t.TempDir()
	for _, d := range []string{"ok", "ask", "ask/pub"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("unix", filepath.Join(dir, d, "s"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
	}

	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// s: rules on paths; any: an allow for every unix socket; tie: an ask
	// and an allow for every unix socket.
	s, any, tie := newSession(t, l), newSession(t, l), newSession(t, l)
	for _, x := range []*Session{s, any, tie} {
		if err := x.Mediate(true, false, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Sync([]Rule{devNull,
		{Path: dir, Tree: true, Net: true},
		{Path: dir + "/ask", Tree: true, Net: true, Ask: true},
		{Path: dir + "/ask/pub", Tree: true, Net: true},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := any.Sync([]Rule{devNull, {Path: dir + "/ask", Tree: true, Net: true, Ask: true}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := any.SyncUnix(UnixRules{AnyUnix: []UnixAnyRule{{}}}); err != nil {
		t.Fatal(err)
	}
	if err := tie.Sync([]Rule{devNull, {Path: dir + "/ok", Tree: true, Net: true}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := tie.SyncUnix(UnixRules{AnyUnix: []UnixAnyRule{{}, {Ask: true}}}); err != nil {
		t.Fatal(err)
	}
	go s.Events(func(e Event) { t.Logf("event: %+v %+v %+v", e, e.Inet, e.Unix) })

	cases := []struct {
		op               string
		ok, anyOK, tieOK bool // in s, any, tie
	}{
		{"unix " + dir + "/ok/s", true, true, true},
		{"unix " + dir + "/ask/s", false, false, false},
		{"unix " + dir + "/ask/pub/s", true, false, false},
	}
	var ops []string
	for _, c := range cases {
		ops = append(ops, c.op)
	}
	for _, x := range []*Session{s, any, tie} {
		got := netMember(t, x, ops...)
		for i, c := range cases {
			want := c.ok
			switch x {
			case any:
				want = c.anyOK
			case tie:
				want = c.tieOK
			}
			if (got[i] == "ok") != want {
				t.Errorf("session %d: %s: %s, want ok=%v", x.id, c.op, got[i], want)
			}
		}
	}
}
