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
)

// SpecSyntax describes the syntax ParseSpec reads, for help texts.
const SpecSyntax = `VERDICT KIND VALUE [for DURATION]
  VERDICT    allow, deny or ask
  write P    writing the file P (creating, deleting... it too); P/** the tree below P
  exec P     running the program P; P/** every program below P
  connect N  a destination: tcp:1.2.3.4:443, [2001:db8::1]:22, unix:/run/x.sock, unix:@name, all...
  proc N C   /proc/<pid>/N of the processes named C
  unknown    the paths that could not be read (lite mode)
  DURATION   e.g. 10m or 2h; without it, until removed
  Quote a value with a blank or another character than letters, digits and
  / . _ - + * ~ @ : = % [ ]: "/home/u/My Documents/**" (escapes: \" \\ \$ \t...).`

// ParseSpec reads a rule written the way Spec writes it, with an optional
// "for DURATION" suffix setting its expiry from now:
//
//	allow write /home/u/src/**
//	allow write "/home/u/My Documents/**"
//	deny exec /usr/bin/curl for 1h
//	ask connect tcp:140.82.112.21:443
//	allow proc oom_score_adj chrome
//
// The words are those of lex, without variables; a comment is ignored.
// The kinds are the ops of hallpass-request and the categories of
// --mediate. The ops come from the kind: every file and network op for
// write, proc and unknown (like an answer), the network ones for
// connect, exec for exec.
func ParseSpec(s string, now time.Time) (Rule, error) {
	ws, _, err := lex(s, nil)
	if err != nil {
		return Rule{}, err
	}
	return parseWords(ws, now)
}

// ParseSpecArgs is ParseSpec for a rule given as command-line arguments:
// a single argument is the text of the rule, several are its words,
// unquoted by the shell already (allow write "/a b").
func ParseSpecArgs(args []string, now time.Time) (Rule, error) {
	if len(args) == 1 {
		return ParseSpec(args[0], now)
	}
	ws := make([]word, len(args))
	for i, a := range args {
		ws[i] = word{s: a, bare: true}
	}
	return parseWords(ws, now)
}

// parseWords reads the rule of words ws.
func parseWords(ws []word, now time.Time) (Rule, error) {
	var r Rule
	if n := len(ws); n >= 2 && ws[n-2].bare && ws[n-2].s == "for" {
		d, err := time.ParseDuration(ws[n-1].s)
		if err != nil {
			return r, fmt.Errorf("for %s: not a duration (10m, 2h...)", quote(ws[n-1].s))
		}
		if d <= 0 {
			return r, fmt.Errorf("for %s: the duration must be positive", quote(ws[n-1].s))
		}
		r.Expires = now.Add(d)
		ws = ws[:n-2]
	}
	if len(ws) == 0 {
		return r, errors.New("empty rule: want allow, deny or ask, a kind and a value")
	}
	verdict := ws[0].s
	switch verdict {
	case "allow":
		r.Verdict = Allow
	case "deny":
		r.Verdict = Deny
	case "ask":
		r.Verdict = Ask
	default:
		return r, fmt.Errorf("%s: want allow, deny or ask first", quote(verdict))
	}
	if len(ws) < 2 {
		return r, fmt.Errorf("%s: want write, exec, connect, proc or unknown after it", verdict)
	}
	kind, vals := ws[1].s, ws[2:]
	value := ""
	if kind != "proc" {
		switch len(vals) {
		case 0:
		case 1:
			value = vals[0].s
		default:
			return r, fmt.Errorf("%s %s: %d words: quote a value with a blank in it (\"/home/u/My Documents/**\")", verdict, quote(kind), len(vals))
		}
	}
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
		if len(vals) == 0 || len(vals) > 2 || vals[0].s == "" || strings.Contains(vals[0].s, "/") {
			return r, fmt.Errorf("%s proc: want a /proc file name, then a process name (quoted if it has a blank)", verdict)
		}
		r.Object.Proc, r.Ops = &ProcMatch{Name: vals[0].s}, OpAll
		if len(vals) == 2 {
			r.Object.Proc.Comm = vals[1].s
		}
	case "unknown":
		if len(vals) != 0 {
			return r, fmt.Errorf("%s unknown: takes no value", verdict)
		}
		r.Object.Unknown, r.Ops = true, OpAll
	default:
		return r, fmt.Errorf("%s: want write, exec, connect, proc or unknown after %s", quote(kind), verdict)
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
		p := o.Path.Path
		if o.Path.Tree {
			p = strings.TrimSuffix(p, "/") + "/**"
		}
		s += quote(p)
	case o.Proc != nil:
		s += "proc " + quote(o.Proc.Name)
		if o.Proc.Comm != "" {
			s += " " + quote(o.Proc.Comm)
		}
	case o.Unknown:
		s += "unknown"
	case o.IsNet():
		s += "connect " + quote(o.NetString())
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

// Editable reports whether r reads back from its EditSpec at now. Quotes
// write any path or name, with escapes for the characters that are not
// printable (an escape sequence, a bidi override shows as \x1b, \u202e),
// but not everything: a file named "**", a rule with ops of two kinds, an
// IPv6 zone... Such a rule can be removed, not edited as text.
func (r Rule) Editable(now time.Time) bool {
	spec := r.EditSpec(now)
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
