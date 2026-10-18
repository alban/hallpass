// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
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

// bold highlights s in an overlay line, keeping the overlay's reverse video.
func bold(s string) string { return "\x1b[1m" + s + "\x1b[22m" }

func redBold(s string) string { return "\x1b[1;31m" + s + "\x1b[39m\x1b[22m" }

// Ask shows the overlay and waits for a key, or for ctx to end.
func (a *Terminal) Ask(ctx context.Context, r Request) Answer {
	head := func(waiting int) string {
		h := bold(fmt.Sprintf(" hallpass: %s (pid %d) wants to %s", sanitize(baseName(r.Exe)), r.PID, r.Op))
		if waiting > 0 {
			h += fmt.Sprintf("   (+%d waiting)", waiting)
		}
		return h
	}
	lines := []string{head(r.Waiting), " " + sanitize(r.Path)}
	if r.Warn != "" {
		lines = append(lines, " "+redBold("[!] "+sanitize(r.Warn)))
	}
	if d := r.Details(); d != "" {
		lines = append(lines, " ("+d+")")
	}
	if o := r.Origin(); o != "" {
		lines = append(lines, " by: "+o)
	}
	keys := " " + bold("[o]") + " allow once"
	accept := "oOdDnN\x1b\x03"
	if r.Scope != "" {
		lines = append(lines, fmt.Sprintf(" [t] and [a] allow: %s", sanitize(r.Scope)))
		keys += fmt.Sprintf("  %s for %v  %s always", bold("[t]"), TempGrant, bold("[a]"))
		accept += "tTaA"
	}
	keys += fmt.Sprintf("  %s deny  %s never  %s dismiss", bold("[d]"), bold("[n]"), bold("[Esc]"))
	if a.timeout > 0 {
		keys += fmt.Sprintf("   (dismissed in %v)", a.timeout)
	}
	lines = append(lines, keys)
	var relabel chan []string
	if r.More != nil {
		relabel = make(chan []string)
		done := make(chan struct{})
		defer close(done)
		go func() {
			for {
				select {
				case n := <-r.More:
					l := append([]string(nil), lines...)
					l[0] = head(n)
					select {
					case relabel <- l:
					case <-done:
						return
					}
				case <-done:
					return
				}
			}
		}()
	}
	switch a.t.Prompt(lines, accept, typeaheadGuard, a.timeout, ctx.Done(), relabel) {
	case 'o', 'O':
		return AnswerAllowOnce
	case 't', 'T':
		return AnswerAllowTemp
	case 'a', 'A':
		return AnswerAllowAlways
	case 'd', 'D':
		return AnswerDenyOnce
	case 'n', 'N':
		return AnswerNever
	}
	return AnswerDismissed
}

// Close is a no-op: the terminal is restored by its owner after the program
// exits.
func (a *Terminal) Close() error { return nil }
