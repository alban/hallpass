// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"os"
	"strings"
	"testing"
)

func TestTitleFilter(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "hello\r\n", "hello\r\n"},
		{"osc0 bel", "a\x1b]0;user@host: ~\x07b", "a\x1b]0;[hallpass] user@host: ~\x07b"},
		{"osc2 st", "\x1b]2;vim\x1b\\", "\x1b]2;[hallpass] vim\x1b\\"},
		{"osc1", "\x1b]1;icon\x07", "\x1b]1;[hallpass] icon\x07"},
		{"empty title", "\x1b]2;\x07", "\x1b]2;[hallpass] \x07"},
		{"other osc", "\x1b]7;file://h/d\x1b\\\x1b]52;c;?\x07", "\x1b]7;file://h/d\x1b\\\x1b]52;c;?\x07"},
		{"osc 22 not title", "\x1b]22;x\x07", "\x1b]22;x\x07"},
		{"csi passes", "\x1b[1;31mred\x1b[0m\x1b[?1049h", "\x1b[1;31mred\x1b[0m\x1b[?1049h"},
		{"title ended by esc", "\x1b]0;t\x1b[1m", "\x1b]0;[hallpass] t\x1b\\\x1b[1m"},
		{"title aborted", "\x1b]0;t\x18x", "\x18x"},
		{"unbalanced pop dropped", "\x1b[23;0tx", "x"},
		{"balanced push pop", "\x1b[22;0t\x1b[23;0t\x1b[23;0t", "\x1b[22;0t\x1b[23;0t"},
		{"other window op", "\x1b[8;24;80t", "\x1b[8;24;80t"},
		{"double esc", "\x1b\x1b]0;t\x07", "\x1b\x1b]0;[hallpass] t\x07"},
		{"esc other", "\x1b7\x1b8\x1bM", "\x1b7\x1b8\x1bM"},
	} {
		var f titleFilter
		// Byte by byte, and at once: reads may split sequences anywhere.
		var split []byte
		for i := range len(tc.in) {
			split = append(split, f.filter([]byte(tc.in[i:i+1]))...)
		}
		if string(split) != tc.want {
			t.Errorf("%s, byte by byte: got %q, want %q", tc.name, split, tc.want)
		}
		var g titleFilter
		if got := string(g.filter([]byte(tc.in))); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestTitleFilterLong(t *testing.T) {
	var f titleFilter
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	got := f.filter([]byte("\x1b]2;" + string(long) + "\x07"))
	if len(got) > maxTitle+len(TitlePrefix)+1 || string(got[:4+len(TitlePrefix)]) != "\x1b]2;"+TitlePrefix {
		t.Errorf("long title not truncated with prefix: %d bytes, starts %q", len(got), got[:20])
	}
	if got := f.filter([]byte("\x1b]52;c;" + string(long) + "\x07")); len(got) != 5000+8 {
		t.Errorf("long non-title osc changed: %d bytes", len(got))
	}
}

func TestTitleStartEnd(t *testing.T) {
	var f titleFilter
	if got, want := f.titleStart("ba\x1bsh"), "\x1b[22;0t\x1b]0;[hallpass] bash\x07"; got != want {
		t.Errorf("titleStart = %q, want %q", got, want)
	}
	f.filter([]byte("\x1b[22;0t"))
	if got, want := f.titleEnd(), "\x1b[23;0t\x1b[23;0t"; got != want {
		t.Errorf("titleEnd = %q, want %q", got, want)
	}
}

func TestTitleSuffix(t *testing.T) {
	var f titleFilter
	f.suffix = " — vim a.txt"
	got := string(f.filter([]byte("\x1b]2;~/src\x07\x1b]1;icon\x07")))
	if want := "\x1b]2;[hallpass] ~/src — vim a.txt\x07\x1b]1;[hallpass] icon\x07"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	f.suffix = ""
	if got, want := f.current(), "\x1b]2;[hallpass] ~/src\x07"; got != want {
		t.Errorf("current = %q, want %q", got, want)
	}
}

func TestFgSuffix(t *testing.T) {
	for _, s := range []string{"bash", "-bash", "/bin/sh", "/usr/bin/zsh"} {
		if !isShell(s) {
			t.Errorf("%s is a shell", s)
		}
	}
	if isShell("vim") {
		t.Error("vim is not a shell")
	}
	// This test binary is not a shell.
	if got := fgSuffix(os.Getpid()); !strings.HasPrefix(got, " — ") || !strings.Contains(got, ".test") {
		t.Errorf("fgSuffix(self) = %q", got)
	}
	if got := fgSuffix(0x7ffffff0); got != "" {
		t.Errorf("fgSuffix(missing) = %q", got)
	}
}
