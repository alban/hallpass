// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package tty

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// TitlePrefix starts every window title the program sets, so the user can
// tell which terminal tabs run in a sandbox.
const TitlePrefix = "[hallpass] "

// maxTitle bounds the title kept while its sequence is incomplete; the rest
// is dropped.
const maxTitle = 1024

// titleFilter rewrites the program's output so that every title it sets
// (OSC 0, 1, 2) starts with TitlePrefix and, for window titles, ends with
// suffix: the command running in the foreground, when it is not a shell. It
// also keeps the program from popping the title hallpass pushed when it
// started (CSI 23 t without a matching CSI 22 t), which would show the user's
// title without the prefix. Other sequences pass through unchanged.
type titleFilter struct {
	state  int
	buf    []byte // the sequence being examined, not yet passed on
	depth  int    // titles pushed by the program and not popped yet
	last   string // the last window title the program set
	suffix string
}

const (
	tfGround   = iota
	tfEsc      // after ESC
	tfOSCNum   // ESC ] and digits
	tfTitle    // ESC ] 0/1/2 ; text
	tfTitleEsc // ESC inside a title (maybe ST)
	tfOSCPass  // another OSC: passed through until its end
	tfCSI      // ESC [ ...
	tfCSIPass  // a long CSI: passed through until its final byte
)

// filter returns p rewritten. Bytes of an unfinished sequence are kept for the
// next call.
func (f *titleFilter) filter(p []byte) []byte {
	if f.state == tfGround && bytes.IndexByte(p, 0x1b) < 0 {
		return p
	}
	out := make([]byte, 0, len(p)+len(TitlePrefix))
	for _, b := range p {
		out = f.step(out, b)
	}
	return out
}

func (f *titleFilter) flush(out []byte) []byte {
	out = append(out, f.buf...)
	f.buf = f.buf[:0]
	return out
}

func (f *titleFilter) step(out []byte, b byte) []byte {
	if (b == 0x18 || b == 0x1a) && f.state != tfGround {
		// CAN, SUB: the terminal aborts the sequence. A title is dropped
		// rather than passed on unprefixed.
		if f.state == tfTitle || f.state == tfTitleEsc {
			f.buf = f.buf[:0]
		}
		f.state = tfGround
		return append(f.flush(out), b)
	}
	switch f.state {
	case tfGround:
		if b == 0x1b {
			f.state = tfEsc
			f.buf = append(f.buf[:0], b)
			return out
		}
		return append(out, b)
	case tfEsc:
		switch b {
		case ']':
			f.state = tfOSCNum
			f.buf = append(f.buf, b)
		case '[':
			f.state = tfCSI
			f.buf = append(f.buf, b)
		case 0x1b:
			out = f.flush(out)
			f.buf = append(f.buf, b)
		default:
			f.state = tfGround
			out = append(f.flush(out), b)
		}
		return out
	case tfOSCNum:
		switch {
		case b >= '0' && b <= '9' && len(f.buf) < 8:
			f.buf = append(f.buf, b)
		case b == ';':
			switch string(f.buf[2:]) {
			case "0", "1", "2":
				f.state = tfTitle
				f.buf = append(f.buf, b)
				return out
			}
			fallthrough
		default:
			out = f.flush(out)
			return f.oscPass(out, b)
		}
		return out
	case tfTitle:
		switch b {
		case 0x07:
			f.state = tfGround
			return f.title(out, "\x07")
		case 0x1b:
			f.state = tfTitleEsc
		default:
			if len(f.buf) < maxTitle {
				f.buf = append(f.buf, b)
			}
		}
		return out
	case tfTitleEsc:
		// Terminals end the title at any ESC: ESC \ is ST, anything else
		// also starts a new sequence.
		f.state = tfGround
		out = f.title(out, "\x1b\\")
		if b != '\\' {
			out = f.step(out, 0x1b)
			out = f.step(out, b)
		}
		return out
	case tfOSCPass:
		return f.oscPass(out, b)
	case tfCSI:
		f.buf = append(f.buf, b)
		switch {
		case b >= 0x40 && b <= 0x7e:
			f.state = tfGround
			if b == 't' && !f.titleStack() {
				f.buf = f.buf[:0]
				return out
			}
			return f.flush(out)
		case len(f.buf) > 64:
			f.state = tfCSIPass
			return f.flush(out)
		}
		return out
	case tfCSIPass:
		if b >= 0x40 && b <= 0x7e {
			f.state = tfGround
		}
		return append(out, b)
	}
	return out
}

// oscPass passes b, a byte of an OSC that is not a title.
func (f *titleFilter) oscPass(out []byte, b byte) []byte {
	switch b {
	case 0x07:
		f.state = tfGround
	case 0x1b:
		// Maybe ST: decided in tfEsc, which passes it on either way.
		f.state = tfEsc
		f.buf = append(f.buf[:0], b)
		return out
	default:
		f.state = tfOSCPass
	}
	return append(out, b)
}

// title passes the title in buf with the prefix (and the suffix, for a window
// title), ended by term.
func (f *titleFilter) title(out []byte, term string) []byte {
	i := bytes.IndexByte(f.buf, ';') + 1
	text := f.buf[i:]
	out = append(out, f.buf[:i]...)
	out = append(out, TitlePrefix...)
	out = append(out, text...)
	if ps := string(f.buf[2 : i-1]); ps != "1" {
		f.last = string(text)
		out = append(out, f.suffix...)
	}
	out = append(out, term...)
	f.buf = f.buf[:0]
	return out
}

// current returns the sequence setting the window title again, after the
// suffix changed.
func (f *titleFilter) current() string {
	return "\x1b]2;" + TitlePrefix + f.last + f.suffix + "\x07"
}

// titleStack tracks the window manipulation sequence in buf (CSI ... t) and
// reports whether to pass it on: a pop (CSI 23 ; ... t) without a push of the
// program's own is dropped.
func (f *titleFilter) titleStack() bool {
	op, _, _ := strings.Cut(string(f.buf[2:len(f.buf)-1]), ";")
	switch op {
	case "22":
		f.depth++
	case "23":
		if f.depth == 0 {
			return false
		}
		f.depth--
	}
	return true
}

// titleStart pushes the user's title and sets one saying the sandbox runs
// name; titleEnd pops back to the user's title.
func (f *titleFilter) titleStart(name string) string {
	f.last = printable(name, 256)
	return "\x1b[22;0t\x1b]0;" + TitlePrefix + f.last + "\x07"
}

// printable returns s without control characters, cut to max bytes.
func printable(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	for len(s) > max {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}

func (f *titleFilter) titleEnd() string {
	return strings.Repeat("\x1b[23;0t", f.depth+1)
}

// fgSuffix returns the title suffix for the foreground process group pgid:
// " — " and its command line, or "" for a shell, as Ptyxis does for the
// processes it sees, which in a hallpass session is only hallpass.
func fgSuffix(pgid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pgid) + "/cmdline")
	if err != nil || len(b) == 0 {
		return ""
	}
	argv0, _, _ := strings.Cut(string(b), "\x00")
	if isShell(argv0) || argv0 == "hallpass-child" {
		return ""
	}
	cmdline := strings.TrimRight(strings.ReplaceAll(string(b), "\x00", " "), " ")
	return " — " + printable(cmdline, 200)
}

var shells = sync.OnceValue(func() map[string]bool {
	m := map[string]bool{}
	for _, s := range []string{"sh", "bash", "dash", "zsh", "fish", "tcsh", "csh", "ksh", "mksh", "tmux", "screen"} {
		m[s] = true
	}
	if b, err := os.ReadFile("/etc/shells"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "/") {
				m[filepath.Base(l)] = true
			}
		}
	}
	return m
})

func isShell(argv0 string) bool {
	return shells()[filepath.Base(strings.TrimPrefix(argv0, "-"))]
}
