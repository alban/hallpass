// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestGoExec checks that the execve notification works with Go programs:
// they are multithreaded, and the runtime sends SIGURG to preempt busy
// goroutines, which can interrupt a notified syscall. The test binary
// itself is the Go program (goHelper).
func TestGoExec(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t)
	script := `
HALLPASS_E2E_HELPER=spawn "$HP_SELF"
HALLPASS_E2E_HELPER=syscallexec "$HP_SELF"
`
	c := e.cmd(script, "--ask=deny")
	c.Env = append(c.Env, "HP_SELF="+self)
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("hallpass: %v\n%s", err, out)
	}
	for _, want := range []string{"spawn=ok", "syscallexec=ok"} {
		if !strings.Contains(string(out), want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, p := range []string{"/outside-spawn", "/outside-exec"} {
		if _, err := os.Lstat(e.home + p); err == nil {
			t.Errorf("%s was created: no longer mediated", p)
		}
	}
}

// goHelper runs a helper mode of the test binary, as a Go program in the
// sandbox, and returns its exit code.
func goHelper(mode string) int {
	switch mode {
	case "noop":
		return 0
	case "spawn":
		// Many goroutines exec'ing at once, while others keep the
		// scheduler preempting.
		defer spin(4)()
		self, err := os.Executable()
		if err != nil {
			fmt.Println("spawn:", err)
			return 1
		}
		var wg sync.WaitGroup
		errs := make(chan error, 16*5)
		for range 16 {
			wg.Go(func() {
				for range 5 {
					c := exec.Command(self)
					c.Env = append(os.Environ(), "HALLPASS_E2E_HELPER=noop")
					if err := c.Run(); err != nil {
						errs <- err
					}
				}
			})
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			fmt.Println("spawn:", err)
			return 1
		}
		// Still mediated.
		if err := os.WriteFile(os.Getenv("HOME")+"/outside-spawn", nil, 0o600); err == nil {
			fmt.Println("spawn: write outside allowed")
			return 1
		}
		fmt.Println("spawn=ok")
		return 0
	case "syscallexec":
		// Exec from a multithreaded program, from whatever thread runs
		// the goroutine, while the runtime preempts others.
		spin(4)
		time.Sleep(50 * time.Millisecond)
		done := make(chan error)
		go func() {
			done <- syscall.Exec("/bin/sh", []string{"sh", "-c",
				`if echo x 2>/dev/null > "$HOME/outside-exec"; then echo "syscallexec: write outside allowed"; else echo syscallexec=ok; fi`},
				os.Environ())
		}()
		fmt.Println("syscallexec:", <-done)
		return 1
	}
	if mode == "net" {
		return netHelper(os.Args[1:])
	}
	fmt.Println("unknown helper mode", mode)
	return 1
}

// spin starts n busy goroutines, which the Go runtime preempts with
// SIGURG, and returns a function stopping them.
func spin(n int) func() {
	stop := make(chan struct{})
	for range n {
		go func() {
			for x := 0; ; x++ {
				if x%(1<<20) == 0 {
					select {
					case <-stop:
						return
					default:
					}
				}
			}
		}()
	}
	return func() { close(stop) }
}
