// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alban/hallpass/internal/tty"
)

// typeaheadGuard ignores keys pressed right after a prompt appears, which were
// meant for the program.
const typeaheadGuard = 500 * time.Millisecond

// Terminal asks in an overlay on the terminal hallpass relays (see package
// tty).
type Terminal struct {
	t       prompter
	timeout time.Duration

	// OnWeb, if set, opens the session's web UI: prompts offer [w], which
	// keeps the request asked about.
	OnWeb func()
	// Preempt takes functions to run in place of the prompt shown, which
	// comes back afterwards: the web UI's pairing confirmation, which must
	// not wait for the request to be answered.
	Preempt chan func()
}

// prompter is tty.Term's overlay.
type prompter interface {
	Prompt(lines []string, accept string, guard, timeout time.Duration, cancel <-chan struct{}, relabel <-chan []string) byte
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
		h := bold(fmt.Sprintf(" hallpass: %s (pid %d) %s", sanitize(baseName(r.Exe)), r.PID, strings.TrimSuffix(r.Wants(), ":")))
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
	var keys, accept string
	if r.Advance {
		if s := r.AdvanceReason(); s != "" {
			lines = append(lines, " "+ReasonLabel+": "+s)
		}
		keys = fmt.Sprintf(" %s grant %s  %s deny", bold("[g]"), r.AdvanceFor(), bold("[d]"))
		accept = "gGdD\x1b\x03"
	} else {
		keys = " " + bold("[o]") + " allow once"
		accept = "oOdDnN\x1b\x03"
		if r.Scope != "" {
			lines = append(lines, fmt.Sprintf(" [t] and [a] allow: %s", sanitize(r.Scope)))
			keys += fmt.Sprintf("  %s for %v  %s always", bold("[t]"), TempGrant, bold("[a]"))
			accept += "tTaA"
		}
		if r.Group != "" {
			lines = append(lines, fmt.Sprintf(" [g] allows the group: %s", sanitize(r.Group)))
			keys += fmt.Sprintf("  %s group", bold("[g]"))
			accept += "gG"
		}
		keys += fmt.Sprintf("  %s deny  %s never", bold("[d]"), bold("[n]"))
	}
	if a.OnWeb != nil {
		keys += "  " + bold("[w]") + " web UI"
		accept += "wW"
	}
	keys += "  " + bold("[Esc]") + " dismiss"
	if a.timeout > 0 {
		keys += fmt.Sprintf("   (dismissed in %v)", a.timeout)
	}
	lines = append(lines, keys)
	var relabel chan []string
	var waiting atomic.Int64
	waiting.Store(int64(r.Waiting))
	if r.More != nil {
		relabel = make(chan []string)
		done := make(chan struct{})
		defer close(done)
		base := append([]string(nil), lines...)
		go func() {
			for {
				select {
				case n := <-r.More:
					waiting.Store(int64(n))
					l := append([]string(nil), base...)
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
	// The time spent in preempting functions does not count.
	var shown time.Duration
	var key byte
	for {
		left := time.Duration(0)
		if a.timeout > 0 {
			if left = a.timeout - shown; left <= 0 {
				return AnswerTimeout
			}
		}
		stop, quit, watched := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var run func()
		go func() {
			defer close(watched)
			select {
			case run = <-a.Preempt:
				close(stop)
			case <-ctx.Done():
				close(stop)
			case <-quit:
			}
		}()
		start := time.Now()
		// Shown again after a preemption: with the latest count.
		lines[0] = head(int(waiting.Load()))
		key = a.t.Prompt(lines, accept, typeaheadGuard, left, stop, relabel)
		shown += time.Since(start)
		close(quit)
		<-watched
		if run != nil {
			// Even if a key came at the same time: it waits for it.
			run()
		}
		switch {
		case key == 'w' || key == 'W':
			go a.OnWeb()
		case key == 0 && run != nil && ctx.Err() == nil:
		default:
			return a.answer(ctx, r, key, shown)
		}
	}
}

// answer maps the key pressed, 0 for none, to the answer to r.
func (a *Terminal) answer(ctx context.Context, r Request, key byte, shown time.Duration) Answer {
	switch key {
	case 'g', 'G':
		if r.Advance {
			return AnswerGrant
		}
		return AnswerAllowGroup
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
	case 0:
		if a.timeout > 0 && ctx.Err() == nil && shown >= a.timeout {
			return AnswerTimeout
		}
	}
	return AnswerDismissed
}

// Close is a no-op: the terminal is restored by its owner after the program
// exits.
func (a *Terminal) Close() error { return nil }
