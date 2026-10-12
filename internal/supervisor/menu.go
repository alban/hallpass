// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"fmt"
	"os"
	"strings"
)

// notice prints a line for the user, outside any prompt.
func (s *session) notice(msg string) {
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	if s.cfg.TTY != nil {
		// The terminal is in raw mode.
		fmt.Fprint(os.Stderr, "\r\n"+msg+"\r\n")
		return
	}
	fmt.Fprintln(os.Stderr, msg)
}

// menu shows the session's rules over the program's screen (Ctrl-]), until
// a key is pressed. Prompts wait meanwhile.
func (s *session) menu() {
	if !s.menuOpen.CompareAndSwap(false, true) {
		return
	}
	defer s.menuOpen.Store(false)
	s.promptMu.Lock()
	defer s.promptMu.Unlock()
	mode := "lite"
	if s.cfg.LSM != nil {
		mode = "strict"
	}
	deny, allow := s.cfg.Policy.Summary()
	w := s.cfg.TTY.Width() - 1
	lines := []string{fmt.Sprintf(" hallpass, %s mode: the rules of this session", mode)}
	lines = append(lines, wrapList(" Denied:   ", deny, w)...)
	lines = append(lines, wrapList(" Writable: ", allow, w)...)
	if s.wait.active.Load() {
		lines = append(lines, " The command exited; its background processes are still supervised.   [s] stop waiting")
	}
	lines = append(lines, " Anything else is asked. A folder covers everything below it.   [any key] close")
	keys := make([]byte, 0, 255)
	for k := 1; k < 256; k++ {
		keys = append(keys, byte(k))
	}
	if s.cfg.TTY.Prompt(lines, string(keys), 0, 0) == 's' && s.wait.active.Load() {
		s.wait.Stop()
	}
}

// wrapList lays out items after prefix, comma-separated, in lines of at
// most width columns, continuation lines indented like the first item.
func wrapList(prefix string, items []string, width int) []string {
	indent := strings.Repeat(" ", len(prefix))
	var lines []string
	line := prefix
	for i, it := range items {
		if i < len(items)-1 {
			it += ","
		}
		if line != prefix && line != indent && len(line)+1+len(it) > width {
			lines = append(lines, line)
			line = indent
		}
		if line != prefix && line != indent {
			line += " "
		}
		line += it
	}
	return append(lines, line)
}
