// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/vt"
)

// testTerm returns a Term of rows×cols without a pseudo-terminal, and a
// function returning what it wrote to the user's terminal so far.
func testTerm(t *testing.T, rows, cols int) (*Term, func() string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		out <- string(b)
	}()
	tm := &Term{
		out:     w,
		emu:     vt.NewEmulator(cols, rows),
		rows:    rows,
		cols:    cols,
		keys:    make(chan []byte, 16),
		outDone: make(chan struct{}),
		dirty:   make(chan struct{}, 1),
	}
	go func() { _, _ = io.Copy(io.Discard, tm.emu) }()
	t.Cleanup(func() { r.Close() })
	return tm, func() string {
		w.Close()
		return <-out
	}
}

// program emits p as the program's output.
func (t *Term) program(p string) {
	t.mu.Lock()
	t.emit(t.title.filter([]byte(p)))
	t.mu.Unlock()
}

func dismissed() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// TestPromptOrigin checks that the overlay lifts origin mode, which would
// move its absolute positions into the program's margins, and restores it.
func TestPromptOrigin(t *testing.T) {
	tm, written := testTerm(t, 24, 80)
	tm.program("\x1b[5;10r\x1b[?6h")
	tm.Prompt([]string{"question"}, "y", 0, 0, dismissed(), nil)
	out := written()
	open := strings.Index(out, "\x1b7\x1b[?6l\x1b[24;1H")
	closing := strings.LastIndex(out, "\x1b[?6h\x1b8")
	if open < 0 || closing < open {
		t.Errorf("overlay does not lift and restore origin mode: %q", out)
	}
	if !tm.esc.decom {
		t.Error("origin mode lost after the prompt")
	}
}

// TestPromptCancel checks that a sequence the program left unfinished is
// cancelled before the overlay is drawn.
func TestPromptCancel(t *testing.T) {
	tm, written := testTerm(t, 24, 80)
	tm.program("\x1b]777;unfinished")
	start := time.Now()
	tm.Prompt([]string{"question"}, "y", 0, 0, dismissed(), nil)
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("did not wait for the sequence to end: %v", d)
	}
	if out := written(); !strings.HasPrefix(out, "\x1b]777;unfinished\x18\x1b7") {
		t.Errorf("no CAN before the overlay: %q", out)
	}

	tm, written = testTerm(t, 24, 80)
	tm.program("done\x1b[1m")
	tm.Prompt([]string{"question"}, "y", 0, 0, dismissed(), nil)
	if out := written(); strings.Contains(out, "\x18") {
		t.Errorf("CAN outside a sequence: %q", out)
	}
}

// TestMakeRoomMargins checks that the screen is scrolled away from under the
// overlay even when the program set margins and origin mode, which confine
// line feeds and cursor positions to its region.
func TestMakeRoomMargins(t *testing.T) {
	const rows = 24
	tm, written := testTerm(t, rows, 80)
	defer written()
	tm.mu.Lock()
	defer tm.mu.Unlock()
	// Everything above the last row was there before hallpass started.
	tm.markUnknown(rows-1, 0)
	tm.emit([]byte("\x1b[3;20r\x1b[?6h"))
	tm.ov = make([]string, 4)
	tm.makeRoom()
	for y := tm.overlayTop(); y < rows; y++ {
		if tm.rowUnknown(y) {
			t.Errorf("row %d under the overlay is still unknown", y)
		}
	}
	// The emulator is back to the program's origin mode and margins.
	tm.emit([]byte("\x1b[1;1HX"))
	if c := tm.emu.CellAt(0, 2); c == nil || c.Content != "X" {
		t.Errorf("CUP 1;1 did not go to the top margin: origin mode lost")
	}
}

// typeKeys sends keys as key presses once an overlay is shown.
func (t *Term) typeKeys(keys ...string) {
	for {
		t.mu.Lock()
		shown := t.ov != nil
		t.mu.Unlock()
		if shown {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for _, k := range keys {
		t.keys <- []byte(k)
	}
}

func TestReadLine(t *testing.T) {
	tm, written := testTerm(t, 24, 40)
	go tm.typeKeys("x", "\x15", "ab", "\x7f", "\x1b[A", "é", "c\r")
	line, ok := tm.ReadLine([]string{"title", "rule: "}, "old")
	if !ok || line != "aéc" {
		t.Errorf("ReadLine = %q, %v; want \"aéc\", true", line, ok)
	}
	if out := written(); !strings.Contains(out, "rule: old_") || !strings.Contains(out, "rule: aé_") {
		t.Errorf("field not drawn: %q", out)
	}

	tm, _ = testTerm(t, 24, 40)
	go tm.typeKeys("abc", "\x1b")
	if line, ok := tm.ReadLine([]string{"rule: "}, ""); ok {
		t.Errorf("ReadLine = %q after Esc, want cancelled", line)
	}

	tm, written = testTerm(t, 24, 20)
	go tm.typeKeys("\r")
	if line, _ := tm.ReadLine([]string{"rule: "}, "allow write /a/very/long/path"); line != "allow write /a/very/long/path" {
		t.Errorf("ReadLine = %q", line)
	}
	if out := written(); !strings.Contains(out, "rule: …y/long/path_") {
		t.Errorf("long line not scrolled to its end: %q", out)
	}
}
