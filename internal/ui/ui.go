// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package ui presents access prompts to the user and returns their answer.
package ui

import (
	"context"
	"fmt"
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
	// AnswerGrant grants a request made in advance (Request.Advance): Path
	// for Request.For.
	AnswerGrant
	// AnswerTimeout is AnswerDismissed because nobody answered in time; a
	// request made in advance learns why it was denied.
	AnswerTimeout
	// AnswerAllowGroup allows the programs of Request.Group for the rest
	// of the session.
	AnswerAllowGroup
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
	case AnswerGrant:
		return "grant"
	case AnswerTimeout:
		return "timeout"
	case AnswerAllowGroup:
		return "group"
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
	case "grant":
		return AnswerGrant
	case "timeout":
		return AnswerTimeout
	case "group":
		return AnswerAllowGroup
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
	Never string
	// ProgramGroup describes the program group AnswerAllowGroup allows,
	// e.g. "@coreutils (cat, ls, cp, … 104 programs)"; "" hides that
	// choice.
	ProgramGroup string
	// Warn, when set, is a warning about the request (e.g. "SSH keys —
	// secret store"); the prompt shows it in red.
	Warn string
	// Note, when set, is a fact about the request, e.g. "listener started
	// inside the sandbox".
	Note string
	// Detail, when set, qualifies Path, e.g. "udp" for a network address.
	Detail string
	// HostNames, when set, are the host names of a network address in
	// Path, comma-separated and shown before it: "github.com
	// (140.82.112.4:443)". The workload asked its DNS servers about
	// them: display only.
	HostNames string
	Waiting   int // other requests queued behind this one
	// More, if not nil, sends the new value of Waiting while the request
	// is asked about.
	More <-chan int
	// Cmdline and Parents (command names, nearest first) describe the
	// process. Both come from the process itself: display only.
	Cmdline []string
	Parents []string
	// Advance is set for a request the program made in advance, before
	// accessing Path: the answers are AnswerGrant or a denial.
	Advance bool
	// For is how long an advance request asks for; 0: the rest of the
	// session.
	For time.Duration
	// Reason is the advance request's reason, written by the program:
	// display only, as the program's claim.
	Reason string
}

// maxReason bounds AdvanceReason's output.
const maxReason = 300

// AdvanceFor formats For, e.g. "for 10m" or "for the rest of the session".
func (r Request) AdvanceFor() string {
	if r.For == 0 {
		return "for the rest of the session"
	}
	s := r.For.String()
	if t, ok := strings.CutSuffix(s, "m0s"); ok {
		s = t + "m"
	}
	if t, ok := strings.CutSuffix(s, "h0m"); ok {
		s = t + "h"
	}
	return "for " + s
}

// AdvanceReason formats Reason for display, quoted and without control
// characters, or "" if there is none.
func (r Request) AdvanceReason() string {
	if r.Reason == "" {
		return ""
	}
	s := sanitize(r.Reason)
	if len(s) > maxReason {
		s = strings.ToValidUTF8(s[:maxReason], "") + "…"
	}
	return `"` + s + `"`
}

// ReasonLabel introduces AdvanceReason in prompts.
const ReasonLabel = "reason given by the program (unverified)"

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

// Sanitize replaces in s, written by the workload, what could mislead a
// terminal or a reader: control and format characters, invalid UTF-8.
func Sanitize(s string) string { return sanitize(s) }

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
// need a scope, the group answer a group, a request made in advance is
// granted or denied, and only it is granted.
func (r Request) Valid(a Answer) bool {
	if r.Advance {
		return a == AnswerGrant || a == AnswerDenyOnce || a == AnswerDismissed || a == AnswerTimeout
	}
	switch a {
	case AnswerGrant:
		return false
	case AnswerAllowTemp, AnswerAllowAlways:
		return r.Scope != ""
	case AnswerAllowGroup:
		return r.ProgramGroup != ""
	}
	return true
}

// Effective is the answer a counts as for r: a if valid, else "deny" for a
// request made in advance and "allow once" for the others.
func (r Request) Effective(a Answer) Answer {
	switch {
	case r.Valid(a):
		return a
	case r.Advance:
		return AnswerDenyOnce
	}
	return AnswerAllowOnce
}

// Allows reports whether a allows the access asked about.
func (a Answer) Allows() bool {
	switch a {
	case AnswerAllowOnce, AnswerAllowTemp, AnswerAllowAlways, AnswerGrant, AnswerAllowGroup:
		return true
	}
	return false
}

// Asker prompts the user and returns their answer. The supervisor serializes
// calls, so implementations show at most one prompt at a time. When ctx
// ends (another client answered), Ask takes the prompt down and returns;
// its answer is then ignored.
type Asker interface {
	Ask(ctx context.Context, r Request) Answer
	Close() error
}

// AutoDeny answers every prompt with "dismissed" (deny, not remembered). Used
// for --prompt=deny.
type AutoDeny struct{}

// Ask always denies.
func (AutoDeny) Ask(context.Context, Request) Answer { return AnswerDismissed }

// Close is a no-op.
func (AutoDeny) Close() error { return nil }

// AutoAllow answers every prompt with "allow once", and grants requests
// made in advance, for --prompt=allow: an audit run that lets the program
// write and logs what it would have asked.
type AutoAllow struct{}

// Ask always allows, once.
func (AutoAllow) Ask(_ context.Context, r Request) Answer {
	if r.Advance {
		return AnswerGrant
	}
	return AnswerAllowOnce
}

// Close is a no-op.
func (AutoAllow) Close() error { return nil }

// Remote shows nothing: it waits for another client (`hallpass answer`,
// `hallpass web`) to answer, and dismisses the request after Timeout (0:
// never). For --prompt=answer.
type Remote struct {
	Timeout time.Duration
}

// Ask waits for ctx to end, or for the timeout.
func (r Remote) Ask(ctx context.Context, _ Request) Answer {
	var expired <-chan time.Time
	if r.Timeout > 0 {
		t := time.NewTimer(r.Timeout)
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-ctx.Done():
	case <-expired:
		return AnswerTimeout
	}
	return AnswerDismissed
}

// Close is a no-op.
func (Remote) Close() error { return nil }

// Target is Path for display, after HostNames when set: "github.com
// (140.82.112.4:443)".
func (r Request) Target() string {
	if r.HostNames != "" {
		return sanitize(r.HostNames) + " (" + sanitize(r.Path) + ")"
	}
	return sanitize(r.Path)
}

// Wants formats the headline after the process, e.g. "wants to write:"
// (Path follows on the next line), or "wants to connect to".
func (r Request) Wants() string {
	if r.Advance {
		return "asks in advance to " + sanitize(r.Op) + ":"
	}
	if strings.HasSuffix(r.Op, " to") {
		return "wants to " + sanitize(r.Op)
	}
	return "wants to " + sanitize(r.Op) + ":"
}

// Details formats Detail and Note, e.g. "udp" or "tcp, listener started
// inside the sandbox", or "" if both are empty.
func (r Request) Details() string {
	var d []string
	for _, s := range []string{r.Detail, r.Note} {
		if s != "" {
			d = append(d, sanitize(s))
		}
	}
	return strings.Join(d, ", ")
}

// Text formats r for a line-based client such as `hallpass answer`: the
// request, then the choices ending with ": ", and the keys they accept.
// The agent chooses the paths, so they are sanitized: no terminal escapes.
func (r Request) Text() (string, map[string]Answer) {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (pid %d) %s\n  %s\n", sanitize(baseName(r.Exe)), r.PID, r.Wants(), r.Target())
	if r.Warn != "" {
		fmt.Fprintf(&b, "  [!] %s\n", sanitize(r.Warn))
	}
	if r.Advance {
		fmt.Fprintf(&b, "  %s\n", r.AdvanceFor())
		if s := r.AdvanceReason(); s != "" {
			fmt.Fprintf(&b, "  %s: %s\n", ReasonLabel, s)
		}
	}
	if d := r.Details(); d != "" {
		fmt.Fprintf(&b, "  (%s)\n", d)
	}
	if o := r.Origin(); o != "" {
		fmt.Fprintf(&b, "  by: %s\n", o)
	}
	if r.Waiting > 0 {
		fmt.Fprintf(&b, "  (%d more waiting)\n", r.Waiting)
	}
	if r.Advance {
		b.WriteString("[g] grant " + r.AdvanceFor() + "  [d] deny: ")
		return b.String(), map[string]Answer{"g": AnswerGrant, "d": AnswerDenyOnce}
	}
	keys := map[string]Answer{"o": AnswerAllowOnce, "d": AnswerDenyOnce, "n": AnswerNever}
	b.WriteString("[o] allow once  ")
	if r.Scope != "" {
		fmt.Fprintf(&b, "[t] allow %s for %v  [a] always  ", sanitize(r.Scope), TempGrant)
		keys["t"], keys["a"] = AnswerAllowTemp, AnswerAllowAlways
	}
	if r.ProgramGroup != "" {
		fmt.Fprintf(&b, "[g] group %s  ", sanitize(r.ProgramGroup))
		keys["g"] = AnswerAllowGroup
	}
	b.WriteString("[d] deny  [n] never")
	if r.Never != "" {
		fmt.Fprintf(&b, " (%s)", sanitize(r.Never))
	}
	b.WriteString(": ")
	return b.String(), keys
}

func baseName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
