// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// FileRule is a rule of a rule file, or a program group it allows
// ("allow exec @shells"), with its line.
type FileRule struct {
	Line  int
	Rule  Rule   // when Group is ""
	Group string // e.g. "@shells"
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
// in the syntax of ParseSpec, without expiry. Blank lines are ignored, and
// # starts a comment at the beginning of a line or after a blank: a path
// cannot contain " #". "allow exec @name" allows a program group.
//
// In the value, a leading ~ is the home directory, and $NAME or ${NAME} is
// a variable: expand returns its value, or an error for a name it does
// not know (HOME is ~).
func ParseFile(name, text string, expand func(string) (string, error)) ([]FileRule, error) {
	var out []FileRule
	for i, line := range strings.Split(text, "\n") {
		n := i + 1
		fail := func(err error) error { return &FileError{Name: name, Line: n, Err: err} }
		line = stripComment(line)
		if line == "" {
			continue
		}
		verdict, rest := cutWord(line)
		kind, value := cutWord(rest)
		value, err := expandValue(value, expand)
		if err != nil {
			return nil, fail(err)
		}
		if strings.Contains(value, " for ") {
			// ParseSpec would take an invalid duration as part of the
			// path.
			return nil, fail(errors.New("a rule file takes no expiry (for DURATION)"))
		}
		if kind == "exec" && strings.HasPrefix(value, "@") {
			if verdict != "allow" {
				return nil, fail(fmt.Errorf("%s exec %s: a group can only be allowed", verdict, value))
			}
			out = append(out, FileRule{Line: n, Group: value})
			continue
		}
		// The time does not matter: an expiry is refused.
		r, err := ParseSpec(verdict+" "+kind+" "+value, time.Time{})
		if err != nil {
			return nil, fail(err)
		}
		if !r.Expires.IsZero() {
			return nil, fail(errors.New("a rule file takes no expiry (for DURATION)"))
		}
		out = append(out, FileRule{Line: n, Rule: r})
	}
	return out, nil
}

// cutWord cuts s, trimmed, at its first blank (space or tab).
func cutWord(s string) (word, rest string) {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], strings.TrimSpace(s[i+1:])
	}
	return s, ""
}

// stripComment returns line without its comment, trimmed.
func stripComment(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") {
		return ""
	}
	for i := 1; i < len(line); i++ {
		if line[i] == '#' && (line[i-1] == ' ' || line[i-1] == '\t') {
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

// expandValue expands a leading ~ and the variables of v.
func expandValue(v string, expand func(string) (string, error)) (string, error) {
	if v == "~" || strings.HasPrefix(v, "~/") {
		home, err := expand("HOME")
		if err != nil {
			return "", err
		}
		v = home + v[1:]
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] != '$' {
			b.WriteByte(v[i])
			continue
		}
		var name string
		switch {
		case i+1 < len(v) && v[i+1] == '{':
			end := strings.IndexByte(v[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("%q: ${ without }", v)
			}
			name, i = v[i+2:i+end], i+end
		default:
			j := i + 1
			for j < len(v) && (v[j] == '_' || v[j] >= 'A' && v[j] <= 'Z' || v[j] >= 'a' && v[j] <= 'z' || v[j] >= '0' && v[j] <= '9') {
				j++
			}
			name, i = v[i+1:j], j-1
		}
		if name == "" {
			return "", fmt.Errorf("%q: $ without a variable name", v)
		}
		val, err := expand(name)
		if err != nil {
			return "", err
		}
		b.WriteString(val)
	}
	return b.String(), nil
}
