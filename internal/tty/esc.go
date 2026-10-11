// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

// escTracker follows the program's output stream just enough to know whether
// it is between escape sequences and UTF-8 characters, so hallpass never
// injects its own sequences in the middle of one.
type escTracker struct {
	state   int
	utf8Rem int // continuation bytes still expected
}

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
		case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
			t.state = stString
		case b >= 0x20 && b <= 0x2f:
			t.state = stEscInt
		case b == 0x1b:
		default:
			t.state = stGround
		}
	case stEscInt:
		if b >= 0x30 && b <= 0x7e {
			t.state = stGround
		}
	case stCSI:
		if b >= 0x40 && b <= 0x7e {
			t.state = stGround
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
