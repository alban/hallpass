// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
// (TCP listener of the helper), ownunix (abstract listener of the helper).
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
	case "own", "ownmptcp":
		proto := 0
		if kind == "ownmptcp" {
			proto = unix.IPPROTO_MPTCP
			// Without MPTCP support, the plain TCP case again.
			if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, proto); err != nil {
				proto = 0
			} else {
				unix.Close(fd)
			}
		}
		ln, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, proto)
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
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, proto)
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
// network, against listeners of the test, outside the session.
func TestEnforceNet(t *testing.T) {
	needRoot(t)
	if err := Active(); err != nil {
		skip(t, err)
	}
	dir := t.TempDir()
	tcp := func() int {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		return ln.Addr().(*net.TCPAddr).Port
	}
	unixListen := func(netw, addr string) {
		if netw == "unixgram" {
			c, err := net.ListenPacket(netw, addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			return
		}
		ln, err := net.Listen(netw, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
	}
	allowed, other, anyProto := tcp(), tcp(), tcp()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	for _, d := range []string{"ok", "no"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
		unixListen("unix", filepath.Join(dir, d, "s"))
		unixListen("unixgram", filepath.Join(dir, d, "g"))
	}
	abs := fmt.Sprintf("hallpass-test-%d-", os.Getpid())
	for _, n := range []string{"ok", "okdeny", "no"} {
		unixListen("unix", "@"+abs+n)
	}

	l, err := Load(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	s, off, all := newSession(t, l), newSession(t, l), newSession(t, l)
	for _, x := range []*Session{s, all} {
		if err := x.Mediate(true, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := off.Mediate(true, false); err != nil {
		t.Fatal(err)
	}
	if err := s.Sync([]Rule{devNull, {Path: dir + "/ok", Tree: true, Net: true}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncNet(NetRules{
		Inet: []InetRule{
			{Prefix: netip.MustParsePrefix("127.0.0.1/32"), Proto: unix.IPPROTO_TCP, PortLo: uint16(allowed), PortHi: uint16(allowed)},
			{Prefix: netip.MustParsePrefix("127.0.0.0/8"), Proto: unix.IPPROTO_UDP, PortLo: uint16(udpPort), PortHi: uint16(udpPort)},
			{Prefix: netip.MustParsePrefix("127.0.0.1/32"), Proto: unix.IPPROTO_UDP, PortLo: uint16(other), PortHi: uint16(other), Expires: time.Now().Add(-time.Second)},
			// An answer: any protocol.
			{Prefix: netip.MustParsePrefix("127.0.0.1/32"), PortLo: uint16(anyProto), PortHi: uint16(anyProto), Expires: time.Now().Add(time.Hour)},
			// IPv6 only: the IPv4 rules above still apply.
			{Prefix: netip.MustParsePrefix("::/0"), Deny: true},
		},
		Abstract: []AbstractRule{
			{Name: abs + "o", Prefix: true},
			{Name: abs + "okdeny", Deny: true},
		},
		OwnListeners: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*Session{off, all} {
		if err := x.Sync([]Rule{devNull}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := all.SyncNet(NetRules{Inet: []InetRule{{}}, AnyUnix: []UnixAnyRule{{}}}); err != nil {
		t.Fatal(err)
	}
	go s.Events(func(e Event) { t.Logf("event: %+v %+v %+v", e, e.Inet, e.Unix) })

	lo := func(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }
	cases := []struct {
		op    string
		ok    bool // in s
		allOK bool // in all and off
	}{
		{"connect " + lo(allowed), true, true},
		{"connect " + lo(other), false, true},
		{"connect " + lo(anyProto), true, true},
		{"sendto " + lo(anyProto), true, true},
		{"connect6 [::ffff:127.0.0.1]:" + strconv.Itoa(allowed), true, true},
		{"connect6 [::ffff:127.0.0.1]:" + strconv.Itoa(other), false, true},
		{"fastopen " + lo(other), false, true},
		{"sendto " + lo(udpPort), true, true},
		{"sendmsg " + lo(udpPort), true, true},
		{"sendto " + lo(other), false, true},
		{"sendmsg " + lo(other), false, true},
		{"unspec " + lo(other), false, true},
		{"own ", true, true},
		{"ownmptcp ", true, true},
		{"ownunix @" + abs + "own", true, true},
		{"unix " + dir + "/ok/s", true, true},
		{"unix " + dir + "/no/s", false, true},
		{"unixgram " + dir + "/ok/g", true, true},
		{"unixgram " + dir + "/no/g", false, true},
		{"unixconn " + dir + "/ok/g", true, true},
		{"unixconn " + dir + "/no/g", false, true},
		{"unix @" + abs + "ok", true, true},
		{"unix @" + abs + "okdeny", false, true},
		{"unix @" + abs + "no", false, true},
	}
	var ops []string
	for _, c := range cases {
		ops = append(ops, c.op)
	}
	for _, x := range []struct {
		name string
		s    *Session
	}{{"mediated", s}, {"off", off}, {"all", all}} {
		got := netMember(t, x.s, ops...)
		for i, c := range cases {
			want := c.allOK
			if x.s == s {
				want = c.ok
			}
			if (got[i] == "ok") != want {
				t.Errorf("%s: %s: %s, want ok=%v", x.name, c.op, got[i], want)
			}
		}
	}
	time.Sleep(100 * time.Millisecond) // let the events be logged
}

func TestInetTrie(t *testing.T) {
	exp := func(time.Time) uint64 { return 7 }
	tr, err := inetTrie(3, []InetRule{
		{},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8"), Deny: true},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Proto: 6, PortLo: 80, PortHi: 80},
		{Prefix: netip.MustParsePrefix("10.1.0.0/16"), Proto: 6, PortLo: 80, PortHi: 80},
		{Prefix: netip.MustParsePrefix("fd00::/8")},
	}, exp)
	if err != nil {
		t.Fatal(err)
	}
	count := map[uint32]int{}
	for k, v := range tr {
		n := 0
		for _, e := range v.E {
			if e.Expiry != 0 || e.Deny != 0 {
				n++
			}
		}
		count[k.Prefixlen] = n
	}
	// any: 1; 10/8: itself and any; 10.1/16: one merged, 10/8, any;
	// fd00::/8: itself merged with any (same ports and protocol).
	want := map[uint32]int{32: 1, 32 + 96 + 8: 2, 32 + 96 + 16: 3, 32 + 8: 1}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("entries per prefix length: %v, want %v", count, want)
	}

	var many []InetRule
	for i := range netEntries + 1 {
		many = append(many, InetRule{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PortLo: uint16(i + 1), PortHi: uint16(i + 1)})
	}
	if _, err := inetTrie(3, many, exp); err == nil {
		t.Error("too many rules accepted")
	}
}

// TestInetTrieV6 checks that IPv6 prefixes do not match IPv4 addresses,
// stored as IPv4-mapped ones in the same trie.
func TestInetTrieV6(t *testing.T) {
	exp := func(time.Time) uint64 { return 7 }
	tr, err := inetTrie(3, []InetRule{
		{PortLo: 53, PortHi: 53},
		{Prefix: netip.MustParsePrefix("::/0"), Deny: true},
		{Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		// IPv6, as IPv4-mapped addresses: they match nothing.
		{Prefix: netip.PrefixFrom(netip.MustParseAddr("::ffff:0:0"), 96), Deny: true},
		{Prefix: netip.PrefixFrom(netip.MustParseAddr("::ffff:10.0.0.0"), 104), Deny: true},
	}, exp)
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		deny     bool
		lo       uint16
		expiring bool
	}
	got := map[string][]entry{}
	for k, v := range tr {
		p := netip.PrefixFrom(netip.AddrFrom16(k.Addr), int(k.Prefixlen)-32)
		for _, e := range v.E {
			if e.Expiry != 0 || e.Deny != 0 {
				got[p.String()] = append(got[p.String()], entry{e.Deny != 0, e.PortLo, e.Expiry != 0})
			}
		}
		if _, ok := got[p.String()]; !ok {
			got[p.String()] = nil
		}
	}
	slices.SortFunc(got["::/0"], func(a, b entry) int { return int(a.lo) - int(b.lo) })
	slices.SortFunc(got["::ffff:10.0.0.0/104"], func(a, b entry) int { return int(a.lo) - int(b.lo) })
	want := map[string][]entry{
		"::/0":                {{deny: true}, {lo: 53, expiring: true}},
		"::ffff:0.0.0.0/96":   {{lo: 53, expiring: true}},
		"::ffff:10.0.0.0/104": {{expiring: true}, {lo: 53, expiring: true}},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("entries:\n%v\nwant\n%v", got, want)
	}
}

func TestAbstractTrie(t *testing.T) {
	exp := func(time.Time) uint64 { return 7 }
	tr, err := abstractTrie(3, []AbstractRule{
		{Name: "a", Prefix: true},
		{Name: "ab"},
		{Name: "abc", Deny: true},
	}, exp)
	if err != nil {
		t.Fatal(err)
	}
	count := map[uint32]int{}
	for k, v := range tr {
		n := 0
		for _, e := range v.E {
			if e.Expiry != 0 || e.Deny != 0 {
				n++
			}
		}
		count[k.Prefixlen] = n
	}
	// "ab" exact is not copied to "abc".
	want := map[uint32]int{40: 1, 48: 2, 56: 2}
	if fmt.Sprint(count) != fmt.Sprint(want) {
		t.Errorf("entries per prefix length: %v, want %v", count, want)
	}
}
