// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package netdiag

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func sockIno(t *testing.T, c syscall.Conn) uint64 {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := rc.Control(func(fd uintptr) { err = syscall.Fstat(int(fd), &st) }); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// needSockDiag skips on kernels without CONFIG_INET_DIAG or
// CONFIG_UNIX_DIAG, such as the CI's.
func needSockDiag(t *testing.T) {
	t.Helper()
	if err := Supported(); errors.Is(err, unix.ENOENT) {
		t.Skipf("kernel without sock_diag: %v", err)
	}
}

func TestTCPListeners(t *testing.T) {
	needSockDiag(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ino := sockIno(t, ln.(*net.TCPListener))
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	d, err := Open(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ls, err := d.TCPListeners(port)
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort("127.0.0.1:0")
	dst = netip.AddrPortFrom(dst.Addr(), port)
	got := TCPCandidates(ls, dst)
	if len(got) != 1 || got[0] != ino {
		t.Fatalf("candidates %v, want [%d] (listeners %+v)", got, ino, ls)
	}
	held := Held(map[uint64]bool{ino: true}, func(pid int) bool { return pid == os.Getpid() })
	if !held[ino] {
		t.Errorf("listener not held by this process")
	}
	if d := Descendants([]int{os.Getppid()}); !d[os.Getpid()] || !d[os.Getppid()] || d[1] {
		t.Errorf("Descendants of the parent: self %t, parent %t, init %t", d[os.Getpid()], d[os.Getppid()], d[1])
	}
	if held := Held(map[uint64]bool{ino: true}, func(int) bool { return false }); len(held) != 0 {
		t.Errorf("held by nobody: %v", held)
	}
}

func TestTCPCandidates(t *testing.T) {
	ap := netip.MustParseAddrPort
	ls := []TCPListener{
		{Addr: ap("127.0.0.1:80"), Inode: 1},
		{Addr: ap("0.0.0.0:80"), Inode: 2},
		{Addr: ap("[::]:80"), Inode: 3},
		{Addr: ap("[::]:81"), Inode: 4, V6Only: true},
		{Addr: ap("0.0.0.0:81"), Inode: 5},
		{Addr: ap("[::]:82"), Inode: 6},
	}
	for _, tc := range []struct {
		dst  string
		want []uint64
	}{
		{"127.0.0.1:80", []uint64{1}},
		{"127.0.0.2:80", []uint64{2, 3}},
		{"[::1]:80", []uint64{3}},
		{"127.0.0.1:81", []uint64{5}},
		{"[::1]:81", []uint64{4}},
		{"127.0.0.1:82", []uint64{6}},
		{"127.0.0.1:83", nil},
	} {
		got := TCPCandidates(ls, ap(tc.dst))
		if len(got) != len(tc.want) {
			t.Errorf("%s: %v, want %v", tc.dst, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: %v, want %v", tc.dst, got, tc.want)
			}
		}
	}
}

func TestUnixSockets(t *testing.T) {
	needSockDiag(t)
	path := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	name := "hallpass-netdiag-test-" + t.Name()
	abs, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "@" + name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer abs.Close()
	dev, ino, err := SocketFile(os.Getpid(), path)
	if err != nil {
		t.Fatal(err)
	}

	d, err := Open(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ss, err := d.UnixSockets()
	if err != nil {
		t.Fatal(err)
	}
	var gotPath, gotAbs bool
	for _, s := range ss {
		if s.Inode == sockIno(t, ln.(*net.UnixListener)) {
			gotPath = true
			if !s.Listen || s.Type != syscall.SOCK_STREAM || s.Path != path || s.VFSIno != ino || s.VFSDev != dev {
				t.Errorf("path socket %+v; file dev %d ino %d", s, dev, ino)
			}
		}
		if s.Inode == sockIno(t, abs) {
			gotAbs = true
			if !s.Abstract || s.Name != name || s.Type != syscall.SOCK_DGRAM {
				t.Errorf("abstract socket %+v", s)
			}
		}
	}
	if !gotPath || !gotAbs {
		t.Errorf("path socket found %t, abstract %t", gotPath, gotAbs)
	}
}
