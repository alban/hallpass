// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"fmt"
	"time"

	"github.com/alban/hallpass/internal/tty"
)

// typeaheadGuard ignores keys pressed right after a prompt appears, which were
// meant for the program.
const typeaheadGuard = 500 * time.Millisecond

// Terminal asks in an overlay on the terminal hallpass relays (see package
// tty).
type Terminal struct {
	t       *tty.Term
	timeout time.Duration
}

// NewTerminal returns an asker drawing on t.
func NewTerminal(t *tty.Term, timeout time.Duration) *Terminal {
	return &Terminal{t: t, timeout: timeout}
}

// Ask shows the overlay and waits for a key.
func (a *Terminal) Ask(r Request) Answer {
	head := fmt.Sprintf(" hallpass: %s (pid %d) wants to %s", baseName(r.Exe), r.PID, r.Op)
	if r.Waiting > 0 {
		head += fmt.Sprintf("   (+%d waiting)", r.Waiting)
	}
	keys := " [o] allow once"
	accept := "oOdD\x1b\x03"
	if r.Folder != "" {
		keys += fmt.Sprintf("  [t] allow %s for %v  [f] allow %s", r.Folder, TempGrant, r.Folder)
		accept += "tTfF"
	}
	keys += "  [d] deny  [Esc] dismiss"
	if a.timeout > 0 {
		keys += fmt.Sprintf("   (dismissed in %v)", a.timeout)
	}
	switch a.t.Prompt([]string{head, " " + r.Path, keys}, accept, typeaheadGuard, a.timeout) {
	case 'o', 'O':
		return AnswerAllowOnce
	case 't', 'T':
		return AnswerAllowFolderTemp
	case 'f', 'F':
		return AnswerAllowFolder
	case 'd', 'D':
		return AnswerDeny
	}
	return AnswerDismissed
}

// Close is a no-op: the terminal is restored by its owner after the program
// exits.
func (a *Terminal) Close() error { return nil }
