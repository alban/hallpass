// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// SpecSyntax describes the syntax ParseSpec reads, for help texts.
const SpecSyntax = `VERDICT KIND VALUE [for DURATION]
  VERDICT    allow, deny or ask
  write P    writing the file P (creating, deleting... it too); P/** the tree below P
  exec P     running the program P; P/** every program below P
  connect N  a destination: tcp:1.2.3.4:443, [2001:db8::1]:22, unix:/run/x.sock, unix:@name, all...
  proc N C   /proc/<pid>/N of the processes named C
  unknown    the paths that could not be read (lite mode)
  DURATION   e.g. 10m or 2h; without it, until removed`

// ParseSpec reads a rule written the way Spec writes it, with an optional
// "for DURATION" suffix setting its expiry from now:
//
//	allow write /home/u/src/**
//	deny exec /usr/bin/curl for 1h
//	ask connect tcp:140.82.112.21:443
//	allow proc oom_score_adj chrome
//
// The kinds are the ops of hallpass-request and the categories of
// --mediate. The ops come from the kind: every file and network op for
// write, proc and unknown (like an answer), the network ones for
// connect, exec for exec.
func ParseSpec(s string, now time.Time) (Rule, error) {
	var r Rule
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, " for "); i >= 0 {
		dur := strings.TrimSpace(s[i+len(" for "):])
		d, err := time.ParseDuration(dur)
		if err != nil {
			return r, fmt.Errorf("%q: %q is not a duration (10m, 2h...)", s, dur)
		}
		if d <= 0 {
			return r, fmt.Errorf("%q: the duration must be positive", s)
		}
		r.Expires = now.Add(d)
		s = strings.TrimSpace(s[:i])
	}
	verdict, rest, _ := strings.Cut(s, " ")
	switch verdict {
	case "allow":
		r.Verdict = Allow
	case "deny":
		r.Verdict = Deny
	case "ask":
		r.Verdict = Ask
	default:
		return r, fmt.Errorf("%q: want allow, deny or ask first", s)
	}
	kind, value, _ := strings.Cut(strings.TrimSpace(rest), " ")
	value = strings.TrimSpace(value)
	switch kind {
	case "write", "exec":
		m, err := parsePathSpec(value)
		if err != nil {
			return r, fmt.Errorf("%s %s: %w", verdict, kind, err)
		}
		r.Object.Path, r.Ops = m, OpAll
		if kind == "exec" {
			r.Ops = OpExec
		}
	case "connect":
		if value == "own-listeners" {
			r.Object.OwnListener = true
		} else {
			m, err := ParseNet(value)
			if err != nil {
				return r, fmt.Errorf("%s connect: %w", verdict, err)
			}
			r.Object = m
		}
		r.Ops = OpNet
	case "proc":
		name, comm, _ := strings.Cut(value, " ")
		if name == "" || strings.Contains(name, "/") {
			return r, fmt.Errorf("%s proc: want a /proc file name, then a process name", verdict)
		}
		r.Object.Proc, r.Ops = &ProcMatch{Name: name, Comm: strings.TrimSpace(comm)}, OpAll
	case "unknown":
		if value != "" {
			return r, fmt.Errorf("%s unknown: takes no value", verdict)
		}
		r.Object.Unknown, r.Ops = true, OpAll
	default:
		return r, fmt.Errorf("%q: want write, exec, connect, proc or unknown after %s", s, verdict)
	}
	return r, nil
}

func parsePathSpec(s string) (*PathMatch, error) {
	if s == "" {
		return nil, errors.New("missing path")
	}
	m, err := ParsePathMatch(s)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ParsePathMatch reads an absolute path, or with a trailing /** the tree
// below it ("/**" alone: every path). Globs are not supported: "*", "?"
// or "[" elsewhere is an error. The path is cleaned.
func ParsePathMatch(s string) (PathMatch, error) {
	m := PathMatch{Path: s}
	if p, ok := strings.CutSuffix(s, "/**"); ok {
		m.Path, m.Tree = p, true
		if m.Path == "" {
			m.Path = "/"
		}
	}
	if !filepath.IsAbs(m.Path) {
		return PathMatch{}, fmt.Errorf("%q: not an absolute path", s)
	}
	if strings.ContainsAny(m.Path, "*?[") {
		return PathMatch{}, fmt.Errorf("%q: only a trailing /** is supported", s)
	}
	m.Path = filepath.Clean(m.Path)
	return m, nil
}

// Spec writes r in the syntax ParseSpec reads, without its expiry.
func (r Rule) Spec() string {
	s := r.Verdict.String() + " "
	switch o := r.Object; {
	case o.Path != nil:
		if r.Ops&OpExec != 0 {
			s += "exec "
		} else {
			s += "write "
		}
		s += o.Path.Path
		if o.Path.Tree {
			s = strings.TrimSuffix(s, "/") + "/**"
		}
	case o.Proc != nil:
		s += strings.TrimSpace("proc " + o.Proc.Name + " " + o.Proc.Comm)
	case o.Unknown:
		s += "unknown"
	case o.IsNet():
		s += "connect " + o.NetString()
	default:
		s += "?"
	}
	return s
}

// EditSpec writes r for editing: its spec, then the time it has left at now
// rounded down, so that saving the text unchanged does not extend it; less
// than a second left is written as a second, not as no expiry.
func (r Rule) EditSpec(now time.Time) string {
	s := r.Spec()
	if r.Expires.IsZero() {
		return s
	}
	secs := int64(r.Expires.Sub(now) / time.Second)
	switch {
	case secs <= 0:
		s += " for 1s"
	case secs >= 120:
		s += " for " + strconv.FormatInt(secs/60, 10) + "m"
	default:
		s += " for " + strconv.FormatInt(secs, 10) + "s"
	}
	return s
}

// Editable reports whether r reads back from its EditSpec at now. The
// syntax has no quoting: a file named "**", a path with " for " or a
// newline, a rule with ops of two kinds, an IPv6 zone... cannot be written
// in it. Such a rule can be removed, not edited as text. Nor can a rule
// with a control or format character (an escape sequence, a bidi
// override) or invalid UTF-8.
func (r Rule) Editable(now time.Time) bool {
	spec := r.EditSpec(now)
	if !utf8.ValidString(spec) || strings.ContainsFunc(spec, func(c rune) bool {
		return unicode.IsControl(c) || unicode.Is(unicode.Cf, c)
	}) {
		// The text is shown raw in the line editor: no terminal escapes
		// or bidi overrides from a path the workload named (what
		// ui.Sanitize replaces elsewhere).
		return false
	}
	back, err := ParseSpec(spec, now)
	if err != nil || back.Verdict != r.Verdict || back.Expires.IsZero() != r.Expires.IsZero() {
		return false
	}
	if back.Ops != r.Ops && back.relevantOps() != r.relevantOps() {
		return false
	}
	return reflect.DeepEqual(back.Object, r.Object)
}

// EditLabel is the label an edit of r keeps: a program group's goes with
// the rules the group gave.
func (r Rule) EditLabel() string {
	if strings.HasPrefix(r.Label, "@") {
		return ""
	}
	return r.Label
}

// String shows r for people and in errors: its spec, ID, set and expiry.
func (r Rule) String() string {
	s := r.Spec()
	if r.ID != 0 {
		s = "rule " + strconv.FormatUint(r.ID, 10) + " (" + s + ")"
	}
	if r.Set != "" {
		s += " in set " + strconv.Quote(r.Set)
	}
	if !r.Expires.IsZero() {
		s += " until " + r.Expires.Format(time.RFC3339)
	}
	return s
}
