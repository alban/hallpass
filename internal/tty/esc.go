// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"fmt"
	"strconv"
	"strings"
)

// escTracker follows the program's output stream just enough to know whether
// it is between escape sequences and UTF-8 characters, so hallpass never
// injects its own sequences in the middle of one. It also follows the modes
// that change where absolute cursor positions land: origin mode (DECOM) and
// the top and bottom margins (DECSTBM).
type escTracker struct {
	state   int
	utf8Rem int    // continuation bytes still expected
	params  []byte // of the current CSI: parameter and intermediate bytes

	decom      bool
	savedDecom bool // by DECSC, restored by DECRC
	top, bot   int  // margins, 1-based; 0: the default (screen edge)
}

// maxParams bounds the CSI bytes kept: longer sequences are not the ones
// tracked.
const maxParams = 32

const (
	stGround = iota
	stEsc    // after ESC
	stEscInt // ESC + intermediate bytes
	stCSI    // ESC [ ... until final byte
	stString // OSC, DCS, SOS, PM, APC: until BEL or ST
	stStrEsc // ESC inside a string (maybe ST)
)

func (t *escTracker) ground() bool { return t.state == stGround && t.utf8Rem == 0 }

func (t *escTracker) feed(p []byte) {
	for _, b := range p {
		t.step(b)
	}
}

func (t *escTracker) step(b byte) {
	if b == 0x18 || b == 0x1a { // CAN, SUB abort any sequence
		t.state, t.utf8Rem = stGround, 0
		return
	}
	switch t.state {
	case stGround:
		switch {
		case t.utf8Rem > 0 && b&0xc0 == 0x80:
			t.utf8Rem--
		case b == 0x1b:
			t.state, t.utf8Rem = stEsc, 0
		case b&0xe0 == 0xc0:
			t.utf8Rem = 1
		case b&0xf0 == 0xe0:
			t.utf8Rem = 2
		case b&0xf8 == 0xf0:
			t.utf8Rem = 3
		default:
			t.utf8Rem = 0
		}
	case stEsc:
		switch {
		case b == '[':
			t.state = stCSI
			t.params = t.params[:0]
		case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
			t.state = stString
		case b >= 0x20 && b <= 0x2f:
			t.state = stEscInt
		case b == 0x1b:
		default:
			switch b {
			case '7': // DECSC
				t.savedDecom = t.decom
			case '8': // DECRC
				t.decom = t.savedDecom
			case 'c': // RIS
				t.decom, t.savedDecom, t.top, t.bot = false, false, 0, 0
			}
			t.state = stGround
		}
	case stEscInt:
		if b >= 0x30 && b <= 0x7e {
			t.state = stGround
		}
	case stCSI:
		switch {
		case b >= 0x40 && b <= 0x7e:
			if len(t.params) <= maxParams {
				t.csi(b)
			}
			t.state = stGround
		case b >= 0x20 && b <= 0x3f && len(t.params) <= maxParams:
			t.params = append(t.params, b)
		}
	case stString:
		switch b {
		case 0x07:
			t.state = stGround
		case 0x1b:
			t.state = stStrEsc
		}
	case stStrEsc:
		if b == '\\' {
			t.state = stGround
		} else {
			t.state = stString
		}
	}
}

// inSequence reports whether the stream stopped inside an escape sequence or
// a control string.
func (t *escTracker) inSequence() bool { return t.state != stGround }

// csi follows the modes set by the CSI sequence ending in final.
func (t *escTracker) csi(final byte) {
	p := string(t.params)
	switch {
	case final == 'r' && plainParams(p): // DECSTBM
		f := strings.Split(p, ";")
		top, _ := strconv.Atoi(f[0])
		bot := 0
		if len(f) > 1 {
			bot, _ = strconv.Atoi(f[1])
		}
		top = max(top, 1)
		if bot != 0 && top >= bot {
			return // ignored by terminals
		}
		t.top, t.bot = top, bot
		if top == 1 {
			t.top = 0
		}
	case final == 's' && p == "": // SCOSC, as DECSC
		t.savedDecom = t.decom
	case final == 'u' && p == "": // SCORC, as DECRC
		t.decom = t.savedDecom
	case final == 'p' && p == "!": // DECSTR
		t.decom, t.top, t.bot = false, 0, 0
	case (final == 'h' || final == 'l') && strings.HasPrefix(p, "?"):
		set := final == 'h'
		for _, m := range strings.Split(p[1:], ";") {
			switch m {
			case "6":
				t.decom = set
			case "1048", "1049": // save or restore the cursor, as DECSC/DECRC
				if set {
					t.savedDecom = t.decom
				} else {
					t.decom = t.savedDecom
				}
			}
		}
	}
}

// plainParams reports whether p holds only numeric parameters: no private
// marker, no intermediate byte.
func plainParams(p string) bool {
	for _, c := range p {
		if (c < '0' || c > '9') && c != ';' {
			return false
		}
	}
	return true
}

// absolute returns the sequence making cursor positions absolute again: origin
// mode off and, with margins true, no margins either. It moves the cursor.
func (t *escTracker) absolute(margins bool) string {
	s := ""
	if t.decom {
		s += "\x1b[?6l"
	}
	if margins && (t.top != 0 || t.bot != 0) {
		s += "\x1b[r"
	}
	return s
}

// restore returns the sequence undoing absolute(margins). It moves the cursor
// home: follow it with DECRC.
func (t *escTracker) restore(margins bool) string {
	s := ""
	switch {
	case !margins || t.top == 0 && t.bot == 0:
	case t.bot == 0:
		s = fmt.Sprintf("\x1b[%dr", t.top)
	default:
		s = fmt.Sprintf("\x1b[%d;%dr", max(t.top, 1), t.bot)
	}
	if t.decom {
		s += "\x1b[?6h"
	}
	return s
}

// originRow is the 1-based row CUP needs to put the cursor on screen row y
// (0-based) once restore has run.
func (t *escTracker) originRow(y int) int {
	if t.decom {
		return y + 1 - max(t.top-1, 0)
	}
	return y + 1
}
