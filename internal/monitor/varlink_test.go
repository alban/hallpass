// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"bufio"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// ReplaceFD and Return make the fake a fdReplacer: the target is the test
// process itself, so the descriptor is installed with dup3.
func (f *fakeNotifier) ReplaceFD(id uint64, fd, target int, newfdFlags uint32) error {
	if !f.IDValid(id) {
		return unix.ENOENT
	}
	f.mu.Lock()
	f.replaced++
	f.mu.Unlock()
	return unix.Dup3(fd, target, int(newfdFlags))
}

func (f *fakeNotifier) Return(id uint64, val int64) error {
	f.kill(id)
	f.out <- response{id: id, val: val}
	return nil
}

// fakeResolved answers ResolveHostname calls on a unix socket at path
// from table, as systemd-resolved does (NUL-terminated JSON messages),
// and records the calls it gets.
func fakeResolved(t *testing.T, path string, table map[string]string) <-chan string {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	calls := make(chan string, 10)
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
					calls <- strings.TrimSuffix(msg, "\x00")
					for name, reply := range table {
						if strings.Contains(msg, `"name":"`+name+`"`) {
							c.Write([]byte(reply + "\x00"))
						}
					}
				}
			}()
		}
	}()
	return calls
}

// TestVarlinkRelay: an allowed connect to resolved's varlink socket is
// relayed by the monitor, which names the addresses resolved answers;
// the workload's socket keeps its flags. A denied connect is not
// relayed, nor a connect to another socket.
func TestVarlinkRelay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "io.systemd.Resolve")
	other := filepath.Join(dir, "other")
	calls := fakeResolved(t, path, map[string]string{
		"github.com": `{"parameters":{"addresses":[{"ifindex":2,"family":2,"address":[140,82,112,4]}],"name":"github.com","flags":1}}`,
	})
	fakeResolved(t, other, nil)
	names := dnsnames.New(nil, nil)
	fx := setupConfig(t, Config{Mediate: seccomp.Connect, Names: names, ResolveSocket: path}, false)
	f := fx.f
	if _, err := fx.m.Apply(rulesDecision(
		netRule(t, "unix:"+path, rules.Allow),
		netRule(t, "unix:"+other, rules.Allow),
	)); err != nil {
		t.Fatal(err)
	}

	s := sock(t, unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK)
	f.expect(t, f.connect(s, sockaddrUnix(path)), 0)
	if f.replaced != 1 {
		t.Fatalf("%d descriptors replaced, want 1", f.replaced)
	}
	if fl, err := unix.FcntlInt(uintptr(s), unix.F_GETFL, 0); err != nil || fl&unix.O_NONBLOCK == 0 {
		t.Errorf("flags %#o %v: O_NONBLOCK lost", fl, err)
	}
	if fl, err := unix.FcntlInt(uintptr(s), unix.F_GETFD, 0); err != nil || fl&unix.FD_CLOEXEC == 0 {
		t.Errorf("fd flags %#o %v: FD_CLOEXEC lost", fl, err)
	}
	if err := unix.SetNonblock(s, false); err != nil {
		t.Fatal(err)
	}
	call := `{"method":"io.systemd.Resolve.ResolveHostname","parameters":{"name":"github.com","family":0}}`
	if _, err := unix.Write(s, []byte(call+"\x00")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-calls:
		if got != call {
			t.Errorf("resolved got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no call relayed")
	}
	buf := make([]byte, 4096)
	k, err := unix.Read(s, buf)
	if err != nil || !strings.HasSuffix(string(buf[:k]), "}\x00") {
		t.Fatalf("reply %q %v", buf[:k], err)
	}
	// Recorded before the reply was passed on.
	if got := names.Lookup(netip.MustParseAddr("140.82.112.4"), 0); !slices.Equal(got, []string{"github.com"}) {
		t.Errorf("names %q", got)
	}

	// Another socket: continued, not relayed.
	f.expect(t, f.connect(sock(t, unix.AF_UNIX, unix.SOCK_STREAM), sockaddrUnix(other)), 0)
	// Denied: not relayed.
	if _, err := fx.m.Apply(rulesDecision(netRule(t, "unix:"+path, rules.Deny))); err != nil {
		t.Fatal(err)
	}
	f.expect(t, f.connect(sock(t, unix.AF_UNIX, unix.SOCK_STREAM), sockaddrUnix(path)), int32(unix.EACCES))
	if f.replaced != 1 {
		t.Errorf("%d descriptors replaced, want 1", f.replaced)
	}
}
