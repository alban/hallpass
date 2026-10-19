// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"strings"
	"testing"
)

func TestEscTrackerOrigin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       string
		decom    bool
		top, bot int
	}{
		{"none", "hello\x1b[1;31m", false, 0, 0},
		{"decom", "\x1b[?6h", true, 0, 0},
		{"decom off", "\x1b[?6h\x1b[?6l", false, 0, 0},
		{"decom among modes", "\x1b[?25;6;7h", true, 0, 0},
		{"ansi mode 6 is not decom", "\x1b[6h", false, 0, 0},
		{"margins", "\x1b[5;10r", false, 5, 10},
		{"top only", "\x1b[5r", false, 5, 0},
		{"margins reset", "\x1b[5;10r\x1b[r", false, 0, 0},
		{"top 1 is default", "\x1b[1;10r", false, 0, 10},
		{"invalid margins ignored", "\x1b[5;10r\x1b[9;3r", false, 5, 10},
		{"xtrestore is not margins", "\x1b[?6r", false, 0, 0},
		{"decrc restores", "\x1b7\x1b[?6h\x1b8", false, 0, 0},
		{"decrc restores set", "\x1b[?6h\x1b7\x1b[?6l\x1b8", true, 0, 0},
		{"scorc", "\x1b[s\x1b[?6h\x1b[u", false, 0, 0},
		{"alt screen", "\x1b[?1049h\x1b[?6h\x1b[?1049l", false, 0, 0},
		{"decstr", "\x1b[?6h\x1b[5;10r\x1b[!p", false, 0, 0},
		{"ris", "\x1b[?6h\x1b[5;10r\x1bc", false, 0, 0},
		{"split", "\x1b[5;", false, 0, 0},
		{"too long", "\x1b[?" + strings.Repeat(";", 40) + "6h", false, 0, 0},
	} {
		var e escTracker
		e.feed([]byte(tc.in))
		if e.decom != tc.decom || e.top != tc.top || e.bot != tc.bot {
			t.Errorf("%s: decom %v margins %d;%d, want %v %d;%d", tc.name, e.decom, e.top, e.bot, tc.decom, tc.top, tc.bot)
		}
	}
}

func TestEscTrackerSplit(t *testing.T) {
	var e escTracker
	e.feed([]byte("\x1b[5;"))
	if !e.inSequence() {
		t.Error("in a CSI: not in a sequence")
	}
	e.feed([]byte("10r\x1b[?"))
	e.feed([]byte("6h"))
	if !e.decom || e.top != 5 || e.bot != 10 || e.inSequence() {
		t.Errorf("decom %v margins %d;%d inSequence %v", e.decom, e.top, e.bot, e.inSequence())
	}
	e.feed([]byte("\x1b]777;x"))
	if !e.inSequence() {
		t.Error("in an OSC: not in a sequence")
	}
	e.step(0x18)
	if e.inSequence() {
		t.Error("after CAN: still in a sequence")
	}
	e.feed([]byte("é"[:1]))
	if e.inSequence() || e.ground() {
		t.Error("in a UTF-8 character: want not ground, but not in a sequence")
	}
}

func TestEscTrackerAbsolute(t *testing.T) {
	for _, tc := range []struct {
		in                string
		margins           bool
		absolute, restore string
		row               int // originRow(9)
	}{
		{"", true, "", "", 10},
		{"\x1b[?6h", true, "\x1b[?6l", "\x1b[?6h", 10},
		{"\x1b[5;10r", true, "\x1b[r", "\x1b[5;10r", 10},
		{"\x1b[5;10r", false, "", "", 10},
		{"\x1b[5;10r\x1b[?6h", true, "\x1b[?6l\x1b[r", "\x1b[5;10r\x1b[?6h", 6},
		{"\x1b[5;10r\x1b[?6h", false, "\x1b[?6l", "\x1b[?6h", 6},
		{"\x1b[3r", true, "\x1b[r", "\x1b[3r", 10},
		{"\x1b[1;20r", true, "\x1b[r", "\x1b[1;20r", 10},
	} {
		var e escTracker
		e.feed([]byte(tc.in))
		if got := e.absolute(tc.margins); got != tc.absolute {
			t.Errorf("%q: absolute(%v) = %q, want %q", tc.in, tc.margins, got, tc.absolute)
		}
		if got := e.restore(tc.margins); got != tc.restore {
			t.Errorf("%q: restore(%v) = %q, want %q", tc.in, tc.margins, got, tc.restore)
		}
		if got := e.originRow(9); got != tc.row {
			t.Errorf("%q: originRow(9) = %d, want %d", tc.in, got, tc.row)
		}
	}
}
