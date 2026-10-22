// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// FileRule is a line of a rule file: a rule, a program group it allows
// ("allow exec @shells"), or a program group it defines ("group @build
// make cc"), with its line.
type FileRule struct {
	Line int
	Rule Rule // when Group is ""
	// Group is the group allowed, e.g. "@shells", or defined, with
	// Members.
	Group   string
	Members []string // programs as in --allow-exec, for a definition
}

// FileError is an invalid line of a rule file.
type FileError struct {
	Name string // the file, or the policy field
	Line int
	Err  error
}

func (e *FileError) Error() string { return fmt.Sprintf("%s:%d: %v", e.Name, e.Line, e.Err) }
func (e *FileError) Unwrap() error { return e.Err }

// ParseFile reads the rules of a rule file named name: one rule per line,
// in the syntax of ParseSpec, without expiry, or "group @NAME PROGRAM..."
// defining a program group. Blank lines and comments are ignored. The
// words are those of lex, expand giving the variables' values.
func ParseFile(name, text string, expand Expand) ([]FileRule, error) {
	var out []FileRule
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		fail := func(err error) error { return &FileError{Name: name, Line: n, Err: err} }
		ws, _, err := lex(line, expand)
		if err != nil {
			return nil, fail(err)
		}
		switch {
		case len(ws) == 0:
			continue
		case ws[0].s == "group":
			if len(ws) < 3 || !strings.HasPrefix(ws[1].s, "@") {
				return nil, fail(errors.New("group: want group @NAME, then its programs"))
			}
			fr := FileRule{Line: n, Group: ws[1].s}
			for _, w := range ws[2:] {
				fr.Members = append(fr.Members, w.s)
			}
			out = append(out, fr)
			continue
		}
		if k := len(ws); k >= 2 && ws[k-2].bare && ws[k-2].s == "for" {
			return nil, fail(errors.New("a rule file takes no expiry (for DURATION)"))
		}
		if len(ws) == 3 && ws[1].s == "exec" && strings.HasPrefix(ws[2].s, "@") {
			if ws[0].s != "allow" {
				return nil, fail(fmt.Errorf("%s exec %s: a group can only be allowed", quote(ws[0].s), quote(ws[2].s)))
			}
			out = append(out, FileRule{Line: n, Group: ws[2].s})
			continue
		}
		// The time does not matter: an expiry is refused.
		r, err := parseWords(ws, time.Time{})
		if err != nil {
			return nil, fail(err)
		}
		out = append(out, FileRule{Line: n, Rule: r})
	}
	return out, nil
}
