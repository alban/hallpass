// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"slices"
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

// runTerm starts hallpass --ask=term running script on a pty and mirrors its
// output into a screen. done is closed when the output ends.
func runTerm(t *testing.T, e env, script string) (m *os.File, scr *screen, c *exec.Cmd, done chan struct{}) {
	t.Helper()
	m, s := openPTY(t)
	t.Cleanup(func() { m.Close() })

	c = e.cmd(script, "--ask=term", "--timeout=20s")
	c.Stdin, c.Stdout, c.Stderr = s, s, s
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	scr = &screen{emu: vt.NewEmulator(100, 24)}
	go func() {
		buf := make([]byte, 64)
		for {
			if _, err := scr.emu.Read(buf); err != nil {
				return
			}
		}
	}()
	done = make(chan struct{})
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
	return m, scr, c, done
}

func TestTerminalPrompt(t *testing.T) {
	e := newEnv(t)
	// 30 coloured lines fill and scroll the 24-row screen, so the overlay
	// covers real content that must be repainted.
	m, scr, c, done := runTerm(t, e, `for i in $(seq 1 30); do printf '\033[31mline%d\033[0m\n' $i; done; echo a > "$HOME/a" && echo a=ok; echo b > "$HOME/b" 2>/dev/null || echo b=denied; echo after`)

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

// Paths come from the agent: escape sequences in them must not reach the
// terminal, or they could redraw the prompt.
func TestTerminalPromptEscapes(t *testing.T) {
	e := newEnv(t)
	m, scr, c, done := runTerm(t, e, `echo a > "$HOME/x$(printf '\033[2J')y" 2>/dev/null || echo denied`)

	waitFor(t, func() bool { return strings.Contains(scr.rawText(), "wants to write") }, "prompt")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	if raw := scr.rawText(); strings.Contains(raw, "x\x1b[2Jy") {
		t.Errorf("escape sequence from the path reached the terminal: %q", raw)
	}
	if got := scr.text(); !strings.Contains(got, "x?[2Jy") {
		t.Errorf("overlay lacks the sanitized path:\n%s", got)
	}
	m.Write([]byte("d"))
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
}

// Output of other processes keeps showing above the overlay, and the
// terminal ends as if the overlay had never been there.
func TestTerminalPromptLiveOutput(t *testing.T) {
	e := newEnv(t)
	m, scr, c, done := runTerm(t, e, `seq 1 30; (for i in $(seq 1 25); do printf 'tick%d\n' $i; sleep 0.1; done) & sleep 0.3; echo a > "$HOME/a" && echo a=ok; wait; printf '\033[32mgreen\033[0m\n'`)

	waitFor(t, func() bool { return strings.Contains(scr.rawText(), "wants to write") }, "prompt")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	first := scr.text()
	time.Sleep(500 * time.Millisecond)
	second := scr.text()
	if !strings.Contains(second, "wants to write") {
		t.Fatalf("overlay not visible:\n%s", second)
	}
	if first == second {
		t.Fatalf("screen frozen while the overlay is shown:\n%s", second)
	}
	if !strings.Contains(second, " by: ") {
		t.Errorf("overlay lacks the command line:\n%s", second)
	}
	// The screen is full, so new lines appear under the overlay; the view
	// scrolls to keep the cursor line (empty after a newline) right above
	// it, with the newest output just before.
	rows := strings.Split(second, "\n")
	top := slices.IndexFunc(rows, func(r string) bool { return strings.Contains(r, "wants to write") })
	if top < 2 || !strings.HasPrefix(rows[top-2], "tick") || strings.TrimSpace(rows[top-1]) != "" {
		t.Errorf("row above the overlay is not the latest tick:\n%s", second)
	}
	m.Write([]byte("o"))

	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	got := scr.text()
	for _, want := range []string{"tick25", "a=ok", "green"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen lacks %q", want)
		}
	}
	if strings.Contains(got, "wants to write") {
		t.Errorf("overlay left on screen")
	}
	// After the replay, the screen holds every tick in order, with no gaps:
	// the test terminal saw the same stream as without the overlay.
	for i := 8; i <= 25; i++ {
		if !strings.Contains(got, "tick"+strconv.Itoa(i)+"\n") {
			t.Errorf("tick%d missing", i)
		}
	}
	if t.Failed() {
		t.Logf("screen:\n%s", got)
	}
}
