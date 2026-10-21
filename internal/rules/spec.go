// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// SpecSyntax describes the syntax ParseSpec reads, for help texts.
const SpecSyntax = `VERDICT KIND VALUE [for DURATION]
  VERDICT   allow, deny or ask
  path P    the file P; P/** the tree below P
  exec P    running the program P; P/** every program below P
  net N     a destination: tcp:1.2.3.4:443, [2001:db8::1]:22, unix:/run/x.sock, unix:@name, all...
  proc N C  /proc/<pid>/N of the processes named C
  unknown   the paths that could not be read (lite mode)
  DURATION  e.g. 10m or 2h; without it, until removed`

// ParseSpec reads a rule written the way Spec writes it, with an optional
// "for DURATION" suffix setting its expiry from now:
//
//	allow path /home/u/src/**
//	deny exec /usr/bin/curl for 1h
//	ask net tcp:140.82.112.21:443
//	allow proc oom_score_adj chrome
//
// The ops come from the kind: every file and network op for path, proc
// and unknown (like an answer), the network ones for net, exec for exec.
func ParseSpec(s string, now time.Time) (Rule, error) {
	var r Rule
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, " for "); i >= 0 {
		d, err := time.ParseDuration(strings.TrimSpace(s[i+len(" for "):]))
		if err == nil {
			if d <= 0 {
				return r, fmt.Errorf("%q: the duration must be positive", s)
			}
			r.Expires = now.Add(d)
			s = strings.TrimSpace(s[:i])
		}
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
	case "path", "exec":
		m, err := parsePathSpec(value)
		if err != nil {
			return r, fmt.Errorf("%s %s: %w", verdict, kind, err)
		}
		r.Object.Path, r.Ops = m, OpAll
		if kind == "exec" {
			r.Ops = OpExec
		}
	case "net":
		if value == "own-listeners" {
			r.Object.OwnListener = true
		} else {
			m, err := ParseNet(value)
			if err != nil {
				return r, fmt.Errorf("%s net: %w", verdict, err)
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
		return r, fmt.Errorf("%q: want path, exec, net, proc or unknown after %s", s, verdict)
	}
	return r, nil
}

func parsePathSpec(s string) (*PathMatch, error) {
	if s == "" {
		return nil, errors.New("missing path")
	}
	m := &PathMatch{Path: s}
	if p, ok := strings.CutSuffix(s, "/**"); ok {
		m.Path, m.Tree = p, true
		if m.Path == "" {
			m.Path = "/"
		}
	}
	if !filepath.IsAbs(m.Path) {
		return nil, fmt.Errorf("%q: want an absolute path", s)
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
			s += "path "
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
		s += "net " + o.NetString()
	default:
		s += "?"
	}
	return s
}

// EditSpec writes r for editing: its spec, then the time it has left at now
// rounded down, so that saving the text unchanged does not extend it.
func (r Rule) EditSpec(now time.Time) string {
	s := r.Spec()
	if r.Expires.IsZero() {
		return s
	}
	secs := int64(r.Expires.Sub(now) / time.Second)
	switch {
	case secs <= 0:
	case secs >= 120:
		s += " for " + strconv.FormatInt(secs/60, 10) + "m"
	default:
		s += " for " + strconv.FormatInt(secs, 10) + "s"
	}
	return s
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
