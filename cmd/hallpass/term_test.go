// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
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
	return runTermAfter(t, e, "", script)
}

// runTermAfter is runTerm on a screen already showing pre, as when hallpass
// is started from a shell. flags are added to hallpass's.
func runTermAfter(t *testing.T, e env, pre, script string, flags ...string) (m *os.File, scr *screen, c *exec.Cmd, done chan struct{}) {
	t.Helper()
	m, s := openPTY(t)
	t.Cleanup(func() { m.Close() })

	scr = &screen{emu: vt.NewEmulator(100, 24)}
	scr.Write([]byte(pre))
	// Answers to terminal queries (hallpass asks where the cursor is) go
	// back as input, as from a real terminal.
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := scr.emu.Read(buf)
			if err != nil {
				return
			}
			_, _ = m.Write(buf[:n])
		}
	}()

	c = e.cmd(script, append([]string{"--ask=term", "--timeout=20s"}, flags...)...)
	c.Stdin, c.Stdout, c.Stderr = s, s, s
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	s.Close()

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

// TestTerminalPromptAnsweredRemotely checks that an answer from another
// client takes the terminal prompt down.
func TestTerminalPromptAnsweredRemotely(t *testing.T) {
	e := newEnv(t)
	_, scr, c, done := runTerm(t, e, `echo a > "$HOME/a" && echo a=ok; sleep 0.5; echo after`)
	waitFor(t, func() bool { return strings.Contains(scr.text(), "wants to write") }, "prompt")
	p := dialPrompts(t, e, c)
	id, path, err := p.next(time.Second)
	if err != nil || !strings.HasSuffix(path, "/a") {
		t.Fatalf("prompt %q: %v", path, err)
	}
	p.answer(id, "once")
	waitFor(t, func() bool { return !strings.Contains(scr.text(), "[o] allow once") }, "prompt taken down")
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	if got := scr.text(); !strings.Contains(got, "a=ok") || !strings.Contains(got, "after") {
		t.Errorf("screen:\n%s", got)
	}
}

func TestTerminalTitle(t *testing.T) {
	e := newEnv(t)
	_, scr, c, done := runTerm(t, e, `printf '\033]2;mytitle\033\\'; printf '\033[23;0t'; echo end; exec sleep 1.2`)
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	raw := scr.rawText()
	for _, want := range []string{
		"\x1b[22;0t\x1b]0;[hallpass] sh\x07",        // pushed the user's title, then set ours
		"\x1b]2;[hallpass] mytitle\x1b\\",           // the program's title, prefixed
		"\x1b]2;[hallpass] mytitle — sleep 1.2\x07", // then the foreground command
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("output lacks %q:\n%q", want, raw)
		}
	}
	// The program's unbalanced pop is dropped; hallpass pops once at exit.
	if n := strings.Count(raw, "\x1b[23;0t"); n != 1 || !strings.HasSuffix(raw, "\x1b[23;0t") {
		t.Errorf("want a single title pop, at the end:\n%q", raw)
	}
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

// Lines on the screen before hallpass started are not in its emulator; the
// rows under the overlay must still come back when it closes.
func TestTerminalPromptKeepsEarlierLines(t *testing.T) {
	e := newEnv(t)
	var pre strings.Builder
	for i := 1; i <= 23; i++ {
		fmt.Fprintf(&pre, "pre%d\r\n", i)
	}
	m, scr, c, done := runTermAfter(t, e, pre.String(), `echo a > "$HOME/a" && echo a=ok`)

	waitFor(t, func() bool { return strings.Contains(scr.rawText(), "wants to write") }, "prompt")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	// The prompt scrolled the earlier lines up instead of covering them.
	if during := scr.text(); !strings.Contains(during, "pre23\n") {
		t.Errorf("earlier lines not visible above the prompt:\n%s", during)
	}
	m.Write([]byte("o"))
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	got := scr.text()
	for _, want := range []string{"pre21\n", "pre22\n", "pre23\n", "a=ok"} {
		if !strings.Contains(got, want) {
			t.Errorf("screen lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "wants to write") {
		t.Errorf("overlay left on screen:\n%s", got)
	}
}

// A write to a known secret store is still asked about, but the prompt is
// flagged with a red warning label.
func TestTerminalPromptSecretWarning(t *testing.T) {
	e := newEnv(t)
	m, scr, c, done := runTerm(t, e, `echo x >> "$HOME/.ssh/id" 2>/dev/null || echo denied`)

	waitFor(t, func() bool { return strings.Contains(scr.rawText(), "wants to write") }, "prompt")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	if got := scr.text(); !strings.Contains(got, "SSH keys") || !strings.Contains(got, "secret store") {
		t.Errorf("overlay lacks the secret-store warning:\n%s", got)
	}
	if raw := scr.rawText(); !strings.Contains(raw, "\x1b[1;31m") {
		t.Errorf("warning not rendered in red")
	}
	m.Write([]byte("d"))
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	if b, _ := os.ReadFile(e.home + "/.ssh/id"); string(b) != "secret\n" {
		t.Errorf("~/.ssh/id modified despite deny: %q", b)
	}
}

// A prompt shown counts the requests that arrive behind it.
func TestTerminalPromptWaiting(t *testing.T) {
	e := newEnv(t)
	m, scr, c, done := runTerm(t, e, `(echo a > "$HOME/a") 2>/dev/null & sleep 1; (echo b > "$HOME/b") 2>/dev/null & (echo c > "$HOME/c") 2>/dev/null & wait; echo end`)

	waitFor(t, func() bool { return strings.Contains(scr.text(), "wants to write") }, "prompt")
	if got := scr.text(); strings.Contains(got, "waiting)") {
		t.Errorf("first prompt counts requests before they arrive:\n%s", got)
	}
	waitFor(t, func() bool { return strings.Contains(scr.text(), "(+2 waiting)") }, "count of 2")
	m.Write([]byte("d"))
	waitFor(t, func() bool { return strings.Contains(scr.text(), "(+1 waiting)") }, "count of 1")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	m.Write([]byte("d"))
	waitFor(t, func() bool {
		s := scr.text()
		return strings.Contains(s, "wants to write") && !strings.Contains(s, "waiting)")
	}, "last prompt, no count")
	time.Sleep(600 * time.Millisecond) // past the type-ahead guard
	m.Write([]byte("d"))
	if err := c.Wait(); err != nil {
		t.Fatalf("hallpass: %v\n%s", err, scr.text())
	}
	<-done
	if got := scr.text(); !strings.Contains(got, "end") {
		t.Errorf("screen:\n%s", got)
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
