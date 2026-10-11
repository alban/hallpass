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
	// AnswerDeny denies the access and remembers the path for the session.
	AnswerDeny
	// AnswerAllowOnce allows this access.
	AnswerAllowOnce
	// AnswerAllowFolder allows everything under Request.Folder for the
	// rest of the session.
	AnswerAllowFolder
	// AnswerAllowFolderTemp allows everything under Request.Folder for
	// TempGrant. Only offered by `hallpass answer` (desktop notifications
	// are limited to three buttons).
	AnswerAllowFolderTemp
)

// TempGrant is the duration of AnswerAllowFolderTemp.
const TempGrant = 5 * time.Minute

func (a Answer) String() string {
	switch a {
	case AnswerDeny:
		return "deny"
	case AnswerAllowOnce:
		return "allow-once"
	case AnswerAllowFolder:
		return "allow-folder"
	case AnswerAllowFolderTemp:
		return "allow-folder-temp"
	default:
		return "dismissed"
	}
}

// Request describes a pending access awaiting a decision.
type Request struct {
	Exe     string // target executable, for display
	PID     uint32
	Op      string // "write", "delete", "rename", ...
	Path    string // resolved absolute path
	Folder  string // offered by "Allow folder"; "" hides that choice
	Waiting int    // other requests queued behind this one
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
