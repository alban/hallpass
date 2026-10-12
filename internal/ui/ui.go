// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package ui presents access prompts to the user and returns their answer.
package ui

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Answer is the user's response to a prompt.
type Answer int

const (
	// AnswerDismissed means no explicit answer: timeout, notification
	// dismissed, or prompt could not be shown. The access is denied but
	// nothing is remembered, so a later retry asks again.
	AnswerDismissed Answer = iota
	// AnswerDenyOnce denies this access; a later retry asks again.
	AnswerDenyOnce
	// AnswerNever denies this access and, for the rest of the session,
	// every later one of the same kind (the exact path for files, see
	// Request.Never) without asking.
	AnswerNever
	// AnswerAllowOnce allows this access.
	AnswerAllowOnce
	// AnswerAllowTemp allows everything covered by Request.Scope for
	// TempGrant.
	AnswerAllowTemp
	// AnswerAllowAlways allows everything covered by Request.Scope for the
	// rest of the session.
	AnswerAllowAlways
)

// TempGrant is the duration of AnswerAllowTemp.
const TempGrant = 5 * time.Minute

func (a Answer) String() string {
	switch a {
	case AnswerDenyOnce:
		return "deny"
	case AnswerNever:
		return "never"
	case AnswerAllowOnce:
		return "once"
	case AnswerAllowTemp:
		return "temp"
	case AnswerAllowAlways:
		return "always"
	default:
		return "dismiss"
	}
}

// ParseAnswer is the inverse of Answer.String. It also accepts the names used
// before answers were unified ("folder", "folder-temp").
func ParseAnswer(s string) Answer {
	switch s {
	case "deny":
		return AnswerDenyOnce
	case "never":
		return AnswerNever
	case "once":
		return AnswerAllowOnce
	case "temp", "folder-temp":
		return AnswerAllowTemp
	case "always", "folder":
		return AnswerAllowAlways
	}
	return AnswerDismissed
}

// Request describes a pending access awaiting a decision.
type Request struct {
	Exe  string // target executable, for display
	PID  uint32
	Op   string // "write", "delete", "rename", ...
	Path string // resolved absolute path
	// Scope describes what AnswerAllowTemp and AnswerAllowAlways cover,
	// e.g. a folder; "" hides those choices.
	Scope string
	// Never describes what AnswerNever covers.
	Never   string
	Waiting int // other requests queued behind this one
	// Cmdline and Parents (command names, nearest first) describe the
	// process. Both come from the process itself: display only.
	Cmdline []string
	Parents []string
}

// maxCommand bounds Command's output, so a prompt line stays readable.
const maxCommand = 100

// Command formats r's command line for display, quoted like a shell would
// need it, with control characters replaced so the process cannot inject
// terminal escapes. It returns "" when the command line is unknown.
func (r Request) Command() string {
	var b strings.Builder
	for i, a := range r.Cmdline {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(shellQuote(sanitize(a)))
		if b.Len() > maxCommand {
			break
		}
	}
	s := b.String()
	if len(s) > maxCommand {
		s = strings.ToValidUTF8(s[:maxCommand], "") + "…"
	}
	return s
}

// Chain formats r's parents for display, e.g. "make ← node".
func (r Request) Chain() string {
	p := make([]string, len(r.Parents))
	for i, c := range r.Parents {
		p[i] = sanitize(c)
	}
	return strings.Join(p, " ← ")
}

// Origin formats the command and its parents on one line, e.g.
// "sh -c 'echo x >> ~/.bashrc' ← make ← node", or "" if both are unknown.
func (r Request) Origin() string {
	parts := []string{}
	if c := r.Command(); c != "" {
		parts = append(parts, c)
	}
	if c := r.Chain(); c != "" {
		parts = append(parts, c)
	}
	return strings.Join(parts, " ← ")
}

func sanitize(s string) string {
	return strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == utf8.RuneError {
			return '?'
		}
		return c
	}, strings.ToValidUTF8(s, "?"))
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./=:,+@%") == "" {
		return s
	}
	if strings.Contains(s, "'") && !strings.ContainsAny(s, "\"$`\\!") {
		return `"` + s + `"`
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Valid reports whether a is a meaningful answer to r: the scoped grants
// need a scope.
func (r Request) Valid(a Answer) bool {
	return r.Scope != "" || (a != AnswerAllowTemp && a != AnswerAllowAlways)
}

// Asker prompts the user and returns their answer. The supervisor serializes
// calls, so implementations show at most one prompt at a time.
type Asker interface {
	Ask(Request) Answer
	Close() error
}

// AutoDeny answers every prompt with "dismissed" (deny, not remembered). Used
// for --ask=deny.
type AutoDeny struct{}

// Ask always denies.
func (AutoDeny) Ask(Request) Answer { return AnswerDismissed }

// Close is a no-op.
func (AutoDeny) Close() error { return nil }

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
