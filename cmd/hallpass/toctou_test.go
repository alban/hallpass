// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
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

// openatHelper maps a memfd shared with the test, copies $HP_PATH into it
// and opens that path for writing with a raw openat, whose path pointer
// is in the shared page. It appends to the file it opened.
func openatHelper() int {
	fd, err := unix.MemfdCreate("toctou", 0)
	if err == nil {
		err = unix.Ftruncate(fd, 4096)
	}
	if err == nil {
		err = unix.Dup3(fd, toctouFD, 0)
	}
	if err != nil {
		fmt.Println("openat:", err)
		return 1
	}
	mem, err := unix.Mmap(fd, 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		fmt.Println("openat: mmap:", err)
		return 1
	}
	copy(mem, os.Getenv("HP_PATH")) // NUL-terminated by the zeroed page
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

// toctou runs the openat helper on path under hallpass, with a write to
// path asked about. Once asked, which is after hallpass has read the path,
// it calls swap with the session and the helper's pid, then answers
// "once". It returns the helper's output.
func toctou(t *testing.T, e env, mode, path string, swap func(p prompter, pid uint32) error) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c := e.cmd(`HALLPASS_E2E_HELPER=openat "$HP_SELF"`, "--mode="+mode, "--prompt=answer", "--timeout=20s")
	c.Env = append(c.Env, "HP_SELF="+self, "HP_PATH="+path)
	var out strings.Builder
	c.Stdout, c.Stderr = &out, &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	p := dialPrompts(t, e, c)
	req, err := p.nextRequest(10 * time.Second)
	if err == nil && req.Prompt.GetPath() != path {
		err = fmt.Errorf("prompt %v, want %s", req.Prompt, path)
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
	f, err := os.OpenFile(fmt.Sprintf("/proc/%d/fd/%d", pid, toctouFD), os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteAt(append([]byte(path), 0), 0)
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
