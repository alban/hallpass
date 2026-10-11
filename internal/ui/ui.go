// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package ui presents access prompts to the user and returns their answer.
package ui

import "time"

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
