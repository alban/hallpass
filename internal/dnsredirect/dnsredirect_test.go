// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dnsredirect

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/lsm"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if os.Getenv("DNSREDIRECT_HELPER") != "" {
		os.Exit(helper(os.Args[1:]))
	}
	os.Exit(m.Run())
}

// helper sends "query" to server:53, connected or not (style), and
// prints the reply and its source: args are style and server.
func helper(args []string) int {
	style, server := args[0], netip.MustParseAddr(args[1])
	network := "udp4"
	if server.Is6() && !server.Is4In6() {
		network = "udp6"
	}
	dst := netip.AddrPortFrom(server, 53)
	var c *net.UDPConn
	var err error
	switch style {
	case "connected":
		c, err = net.DialUDP(network, nil, net.UDPAddrFromAddrPort(dst))
		if err == nil {
			_, err = c.Write([]byte("query"))
		}
	case "sendto":
		c, err = net.ListenUDP(network, nil)
		if err == nil {
			_, err = c.WriteToUDPAddrPort([]byte("query"), dst)
		}
	case "bound":
		// Bound to an address that cannot reach loopback.
		c, err = net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(args[2])})
		if err == nil {
			_, err = c.WriteToUDPAddrPort([]byte("query"), dst)
		}
	case "tcp":
		var t net.Conn
		if t, err = net.DialTimeout("tcp", dst.String(), 2*time.Second); err == nil {
			fmt.Printf("tcp peer %s\n", t.RemoteAddr())
			t.Close()
		} else {
			fmt.Println("error", err)
		}
		return 0
	}
	if err != nil {
		fmt.Println("error", err)
		return 0
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b := make([]byte, 64)
	k, from, err := c.ReadFromUDPAddrPort(b)
	if err != nil {
		fmt.Println("error", err)
		return 0
	}
	fmt.Printf("%s from %s\n", b[:k], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	return 0
}

func TestCgroup2Path(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		content, want string
		err           error
	}{
		{"0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-abc.scope\n", "/kubepods.slice/kubepods-pod1.slice/cri-containerd-abc.scope", nil},
		{"0::/\n", "", ErrNoCgroup2},
		{"0::/../../x\n", "", ErrNoCgroup2},
		{"12:memory:/docker/abc\n0::/system.slice/docker-abc.scope\n", "", ErrNoCgroup2},
		{"", "", ErrNoCgroup2},
	} {
		p := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := cgroup2Path(p)
		if got != c.want || !errors.Is(err, c.err) {
			t.Errorf("%q: %q %v, want %q %v", c.content, got, err, c.want, c.err)
		}
	}
}

func TestRoute(t *testing.T) {
	for _, c := range []struct {
		rt Route
		ok bool
	}{
		{Route{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddrPort("127.0.0.1:4000")}, true},
		{Route{netip.MustParseAddr("fd00::10"), netip.MustParseAddrPort("[::1]:4000")}, true},
		{Route{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddrPort("[::1]:4000")}, false},
		{Route{netip.MustParseAddr("fd00::10"), netip.MustParseAddrPort("127.0.0.1:4000")}, false},
		{Route{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddrPort("10.0.0.1:4000")}, false},
		{Route{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddrPort("127.0.0.1:0")}, false},
	} {
		_, l, err := route(c.rt)
		if (err == nil) != c.ok {
			t.Errorf("%v: %v", c.rt, err)
		}
		if err == nil && c.rt.Listener.Port() == 4000 && l.Port != 0xa00f {
			t.Errorf("%v: port %#x, want 0xa00f (4000 in network order)", c.rt, l.Port)
		}
	}
	if a := addr6(netip.MustParseAddr("10.96.0.10")); a.A[2] != 0xffff0000 || a.A[3] != 0x0a00600a {
		t.Errorf("addr6 %#x", a.A)
	}
}

// canLoad skips unless the test can load BPF programs and make cgroups:
// root, cgroup v2.
func canLoad(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("not root")
	}
	if err := lsm.Supported(); err != nil && !strings.Contains(err.Error(), "LSM") {
		t.Skipf("no BPF: %v", err)
	}
}

// TestRedirect: a process in the cgroup sends its DNS queries, connected,
// with sendto, or over TCP, to a name server; they reach the listener,
// whose replies come from the server. A socket bound elsewhere, a
// process outside the cgroup, and the cgroup after Close are not
// redirected.
func TestRedirect(t *testing.T) {
	canLoad(t)
	// This process's cgroup v2 directory, the root one too (a VM's
	// init), on a hybrid host too: cgroup v2 is enough for the programs.
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	path := ""
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			path = p
		}
	}
	if path == "" {
		t.Skipf("no cgroup v2: %q", b)
	}
	root := cgroup2Mount(t)
	if _, err := os.Stat(root + path + "/cgroup.procs"); err != nil {
		t.Skipf("own cgroup not under %s: %v", root, err)
	}
	cg, err := os.MkdirTemp(root+path, "hallpass-dnsredirect")
	if err != nil {
		// A cgroup with processes cannot have children with controllers,
		// but can have children: a read-only cgroupfs cannot.
		t.Skipf("make a cgroup: %v", err)
	}
	t.Cleanup(func() { os.Remove(cg) })
	cgfd, err := unix.Open(cg, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(cgfd)

	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	lp := netip.MustParseAddrPort(pc.LocalAddr().String())
	tl, err := net.Listen("tcp4", lp.String())
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		b := make([]byte, 64)
		for {
			k, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("reply to "), b[:k]...), from)
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	server := "192.0.2.53"
	r, err := Attach(cgfd, []Route{{netip.MustParseAddr(server), lp}})
	if errors.Is(err, unix.EPERM) {
		t.Skipf("load: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	run := func(inCgroup bool, args ...string) string {
		t.Helper()
		cmd := exec.Command("/proc/self/exe", args...)
		cmd.Env = append(os.Environ(), "DNSREDIRECT_HELPER=1")
		if inCgroup {
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: cgfd}
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	want := "reply to query from " + server + ":53"
	for _, style := range []string{"connected", "sendto"} {
		if got := run(true, style, server); got != want {
			t.Errorf("%s: %q, want %q", style, got, want)
		}
		// Mapped, from an IPv6 socket.
		if got := run(true, style, "::ffff:"+server); got != want {
			t.Errorf("%s, mapped: %q, want %q", style, got, want)
		}
	}
	if got := run(true, "tcp", server); got != "tcp peer "+lp.String() {
		t.Errorf("tcp: %q", got)
	}
	// Bound to an address that is not a loopback one, outside the
	// cgroup: the query goes to the server (none here: no reply).
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				if got := run(true, "bound", server, n.IP.String()); got == want {
					t.Errorf("bound to %s: redirected", n.IP)
				}
				break
			}
		}
	}
	if got := run(false, "sendto", server); got == want {
		t.Errorf("outside the cgroup: redirected")
	}
	if err := r.Close(); err != nil {
		t.Error(err)
	}
	if got := run(true, "sendto", server); got == want {
		t.Errorf("after Close: redirected")
	}
}

// cgroup2Mount returns where a cgroup v2 file system is mounted,
// mounting one for the test if none is.
func cgroup2Mount(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		for i, x := range f {
			if x == "-" && i+1 < len(f) && f[i+1] == "cgroup2" && len(f) > 4 {
				return f[4]
			}
		}
	}
	dir := t.TempDir()
	if err := unix.Mount("cgroup2", dir, "cgroup2", 0, ""); err != nil {
		t.Skipf("mount cgroup2: %v", err)
	}
	t.Cleanup(func() { unix.Unmount(dir, unix.MNT_DETACH) })
	return dir
}

// TestOpenCgroup: the directory OpenCgroup opens for this process is its
// cgroup, when this process sees the host's cgroup namespace.
func TestOpenCgroup(t *testing.T) {
	canLoad(t)
	path, err := cgroup2Path("/proc/self/cgroup")
	if err != nil {
		t.Skipf("cgroup: %v", err)
	}
	var own, host unix.Stat_t
	if unix.Stat("/proc/self/ns/cgroup", &own) != nil || unix.Stat("/proc/1/ns/cgroup", &host) != nil || own.Ino != host.Ino {
		t.Skip("not in the host's cgroup namespace")
	}
	fd, err := OpenCgroup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var got, want unix.Stat_t
	if err := unix.Fstat(fd, &got); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/sys/fs/cgroup"+path, &want); err != nil {
		t.Skipf("own cgroup not under /sys/fs/cgroup: %v", err)
	}
	if got.Ino != want.Ino {
		t.Errorf("opened inode %d, want %d (%s)", got.Ino, want.Ino, path)
	}
}
