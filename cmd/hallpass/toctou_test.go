// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/alban/hallpass/internal/lsm"
	"golang.org/x/sys/unix"
)

// toctouFD is where the openat helper puts its memfd, for the test to
// open through /proc/<pid>/fd.
const toctouFD = 100

// sharedPage maps a page of a memfd at toctouFD, which the test rewrites
// through /proc/<pid>/fd, and copies b into it.
func sharedPage(b []byte) ([]byte, error) {
	fd, err := unix.MemfdCreate("toctou", 0)
	if err == nil {
		err = unix.Ftruncate(fd, 4096)
	}
	if err == nil {
		err = unix.Dup3(fd, toctouFD, 0)
	}
	if err != nil {
		return nil, err
	}
	mem, err := unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err == nil {
		copy(mem, b)
	}
	return mem, err
}

// openatHelper opens $HP_PATH, copied to the shared page, for writing with
// a raw openat, and appends to the file it opened.
func openatHelper() int {
	mem, err := sharedPage([]byte(os.Getenv("HP_PATH"))) // NUL-terminated by the zeroed page
	if err != nil {
		fmt.Println("openat:", err)
		return 1
	}
	atFDCWD := unix.AT_FDCWD
	r, _, errno := unix.Syscall6(unix.SYS_OPENAT, uintptr(atFDCWD), uintptr(unsafe.Pointer(&mem[0])),
		unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC, 0, 0, 0)
	if errno != 0 {
		fmt.Println("open=" + unix.ErrnoName(errno))
		return 0
	}
	unix.Write(int(r), []byte("toctou\n"))
	fmt.Println("open=ok")
	return 0
}

// connectHelper connects a TCP socket to $HP_PATH, an IPv4 address and
// port, with a raw connect whose sockaddr is in the shared page.
func connectHelper() int {
	mem, err := sharedPage(sockaddr4(os.Getenv("HP_PATH")))
	if err != nil {
		fmt.Println("connect:", err)
		return 1
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("connect:", err)
		return 1
	}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&mem[0])), unix.SizeofSockaddrInet4)
	if errno != 0 {
		fmt.Println("connect=" + unix.ErrnoName(errno))
	} else {
		fmt.Println("connect=ok")
	}
	return 0
}

// sockaddr4 is the struct sockaddr_in of addr.
func sockaddr4(addr string) []byte {
	ap := netip.MustParseAddrPort(addr)
	b := make([]byte, unix.SizeofSockaddrInet4)
	binary.NativeEndian.PutUint16(b, unix.AF_INET)
	binary.BigEndian.PutUint16(b[2:], ap.Port())
	a := ap.Addr().As4()
	copy(b[4:], a[:])
	return b
}

// toctou runs the openat helper on path under hallpass, with a write to
// path asked about. Once asked, which is after hallpass has read the path,
// it calls swap with the session and the helper's pid, then answers
// "once". It returns the helper's output.
func toctou(t *testing.T, e env, mode, path string, swap func(p prompter, pid uint32) error) string {
	return toctouHelper(t, e, mode, "openat", path, swap)
}

// toctouHelper is toctou with another helper, about target.
func toctouHelper(t *testing.T, e env, mode, helper, target string, swap func(p prompter, pid uint32) error, flags ...string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := e.cmd(`HALLPASS_E2E_HELPER=`+helper+` "$HP_SELF"`, append(flags, "--mode="+mode, "--prompt=answer", "--timeout=20s")...)
	c.Env = append(c.Env, "HP_SELF="+self, "HP_PATH="+target)
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	req, err := p.nextRequest(10 * time.Second)
	if err == nil && req.Prompt.GetPath() != target {
		err = fmt.Errorf("prompt %v, want %s", req.Prompt, target)
	}
	if err == nil {
		err = swap(p, req.Prompt.GetPid())
	}
	if err != nil {
		c.Process.Kill()
		c.Wait()
		t.Fatalf("%v\n%s", err, out.String())
	}
	p.answer(req.Id, "once")
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out.String())
	}
	return out.String()
}

// swapPath rewrites the path the openat helper of pid is opening.
func swapPath(pid uint32, path string) error {
	return swapMem(pid, append([]byte(path), 0))
}

// swapMem rewrites the shared page of the helper pid.
func swapMem(pid uint32, b []byte) error {
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/%d", pid, toctouFD), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt(b, 0)
	return err
}

// checkTOCTOU checks the outcome of a path swapped for ~/.ssh/id while
// hallpass asked about another file: strict mode denies the open, as the
// kernel checks the file actually opened. Lite mode only checks the path it
// read, and the kernel opens the swapped one: a documented limitation (see
// docs/how-it-works/lite.md), asserted so that a change of behaviour is noticed.
func checkTOCTOU(t *testing.T, e env, mode, out string) {
	t.Helper()
	secret, err := os.ReadFile(e.home + "/.ssh/id")
	if err != nil {
		t.Fatal(err)
	}
	want, wantSecret := "open=EACCES", "secret\n"
	if mode == "lite" {
		want, wantSecret = "open=ok", "secret\ntoctou\n"
	}
	if !strings.Contains(out, want+"\n") {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
	if string(secret) != wantSecret {
		t.Errorf("~/.ssh/id: %q, want %q", secret, wantSecret)
	}
}

func toctouModes(t *testing.T, test func(t *testing.T, e env, mode string)) {
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
			test(t, newEnv(t), mode)
		})
	}
}

// TestTOCTOUMemory rewrites the path in the workload's memory while
// hallpass asks about it.
func TestTOCTOUMemory(t *testing.T) {
	toctouModes(t, func(t *testing.T, e env, mode string) {
		allowed := e.home + "/allowed"
		if err := os.WriteFile(allowed, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		// Unchanged, "once" lets the helper open the file asked about.
		if out := toctou(t, e, mode, allowed, func(prompter, uint32) error { return nil }); !strings.Contains(out, "open=ok\n") {
			t.Fatalf("unchanged path:\n%s", out)
		}
		out := toctou(t, e, mode, allowed, func(_ prompter, pid uint32) error {
			return swapPath(pid, e.home+"/.ssh/id")
		})
		checkTOCTOU(t, e, mode, out)
		if b, _ := os.ReadFile(allowed); string(b) != "toctou\n" {
			t.Errorf("allowed file: %q, want the unchanged run's write only", b)
		}
	})
}

// TestTOCTOUSymlink swaps a symlink to ~/.ssh/id in place of the file
// hallpass asks about, or of its directory.
func TestTOCTOUSymlink(t *testing.T) {
	swaps := []struct {
		name string
		swap func(d string) error // d/id is the file asked about
	}{
		{"file", func(d string) error {
			if err := os.Symlink(filepath.Dir(d)+"/.ssh/id", d+"/new"); err != nil {
				return err
			}
			return os.Rename(d+"/new", d+"/id")
		}},
		{"dir", func(d string) error {
			if err := os.Rename(d, d+".old"); err != nil {
				return err
			}
			return os.Symlink(filepath.Dir(d)+"/.ssh", d)
		}},
	}
	for _, s := range swaps {
		t.Run(s.name, func(t *testing.T) {
			toctouModes(t, func(t *testing.T, e env, mode string) {
				d := e.home + "/d"
				if err := os.Mkdir(d, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(d+"/id", nil, 0o600); err != nil {
					t.Fatal(err)
				}
				out := toctou(t, e, mode, d+"/id", func(prompter, uint32) error { return s.swap(d) })
				checkTOCTOU(t, e, mode, out)
			})
		})
	}
}

// TestTOCTOUConnect swaps the address of a connect for another one while
// hallpass asks about the first: strict mode denies it, as the kernel only
// lets through the address granted. Lite mode connects (see checkTOCTOU).
func TestTOCTOUConnect(t *testing.T) {
	toctouModes(t, func(t *testing.T, e env, mode string) {
		var addrs []string
		accepted := make(chan string, 2)
		for range 2 {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				if c, err := ln.Accept(); err == nil {
					accepted <- ln.Addr().String()
					c.Close()
				}
			}()
			addrs = append(addrs, ln.Addr().String())
		}
		asked, secret := addrs[0], addrs[1]
		out := toctouHelper(t, e, mode, "connect", asked, func(_ prompter, pid uint32) error {
			return swapMem(pid, sockaddr4(secret))
		}, "--mediate=write,exec,connect")
		want := "connect=EACCES"
		if mode == "lite" {
			want = "connect=ok"
			if got := <-accepted; got != secret {
				t.Errorf("connected to %s, want %s", got, secret)
			}
		}
		if !strings.Contains(out, want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
		select {
		case a := <-accepted:
			t.Errorf("connected to %s", a)
		default:
		}
	})
}
