// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
	"golang.org/x/sys/unix"
)

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.IoctlSetWinsize(int(m.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 100})
	return m, s
}

// screen mirrors what a user's terminal would show.
type screen struct {
	mu  sync.Mutex
	emu *vt.Emulator
	raw strings.Builder
}

func (s *screen) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw.Write(p)
	return s.emu.Write(p)
}

func (s *screen) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.emu.String()
}

func (s *screen) rawText() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.raw.String()
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestTerminalPrompt(t *testing.T) {
	e := newEnv(t)
	m, s := openPTY(t)
	defer m.Close()

	// 30 coloured lines fill and scroll the 24-row screen, so the overlay
	// covers real content that must be repainted.
	c := e.cmd(`for i in $(seq 1 30); do printf '\033[31mline%d\033[0m\n' $i; done; echo a > "$HOME/a" && echo a=ok; echo b > "$HOME/b" 2>/dev/null || echo b=denied; echo after`,
		"--ask=term", "--timeout=20s")
	c.Stdin, c.Stdout, c.Stderr = s, s, s
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	scr := &screen{emu: vt.NewEmulator(100, 24)}
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := scr.emu.Read(buf); err != nil {
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := m.Read(buf)
			if n > 0 {
				scr.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	prompts := 0
	answer := func(key string) {
		prompts++
		waitFor(t, func() bool { return strings.Count(scr.rawText(), "wants to write") >= prompts }, "prompt")
		// Type-ahead guard: an immediate key must be ignored.
		m.Write([]byte("d"))
		time.Sleep(700 * time.Millisecond)
		if !strings.Contains(scr.text(), "wants to write") {
			t.Fatalf("overlay not visible:\n%s", scr.text())
		}
		m.Write([]byte(key))
	}
	answer("o")
	answer("d")

	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	got := scr.text()
	for _, want := range []string{"line12", "line28", "line29", "line30", "a=ok", "b=denied", "after"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen lacks %q", want)
		}
	}
	if strings.Contains(got, "hallpass:") || strings.Contains(got, "[o] allow once") {
		t.Errorf("overlay left on screen")
	}
	if _, err := os.Stat(e.home + "/a"); err != nil {
		t.Error("a was not created")
	}
	if _, err := os.Stat(e.home + "/b"); err == nil {
		t.Error("b was created despite deny")
	}
	if t.Failed() {
		t.Logf("screen:\n%s", got)
	}
}
