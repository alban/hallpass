// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Expand returns the value of a variable of a rule's text ($NAME,
// ${NAME}; HOME for a leading ~), or an error for a name it does not
// know.
type Expand func(name string) (string, error)

// word is a word of a rule's text.
type word struct {
	s string
	// bare is a word written as is, without quotes or variables: only a
	// bare "for" starts an expiry.
	bare bool
}

// bareChar reports whether c can be written outside quotes: letters,
// digits and the punctuation of paths and destinations. Anything else
// (a blank, a quote, a comma, #, $ as such...) needs quotes.
func bareChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsMark(c) ||
		strings.ContainsRune("/._-+*~@:=%[]", c)
}

// lex splits a line of rule text into words, separated by blanks (spaces
// or tabs). A word is made of:
//
//   - bare characters (bareChar);
//   - "..." with the escapes of Go strings, \$ too, and variables;
//   - '...', taken as is;
//   - $NAME or ${NAME}, a variable; ~ at its start, followed by / or
//     nothing, is $HOME.
//
// Quoted text has printable characters only: others are written as
// escapes in "..." (\t, \x1b, \u202e). # at the start of a word starts a
// comment, to the end of the line, returned trimmed. With expand nil, a
// variable is an error.
func lex(s string, expand Expand) (ws []word, comment string, err error) {
	if !utf8.ValidString(s) {
		return nil, "", errors.New("invalid UTF-8")
	}
	blank := func(c byte) bool { return c == ' ' || c == '\t' }
	i := 0
	for {
		for i < len(s) && blank(s[i]) {
			i++
		}
		if i == len(s) {
			return ws, "", nil
		}
		if s[i] == '#' {
			return ws, strings.TrimSpace(s[i+1:]), nil
		}
		var b strings.Builder
		w := word{bare: true}
		start := i
		for i < len(s) && !blank(s[i]) {
			c, size := utf8.DecodeRuneInString(s[i:])
			switch {
			case c == '"':
				w.bare = false
				n, err := lexDouble(s[i+1:], &b, expand)
				if err != nil {
					return nil, "", err
				}
				i += 1 + n
			case c == '\'':
				w.bare = false
				end := strings.IndexByte(s[i+1:], '\'')
				if end < 0 {
					return nil, "", fmt.Errorf("%q: ' without its closing '", s[i:])
				}
				q := s[i+1 : i+1+end]
				if j := strings.IndexFunc(q, func(c rune) bool { return !printable(c) }); j >= 0 {
					return nil, "", fmt.Errorf("%q: unprintable character in '...': write it as an escape in \"...\"", q)
				}
				b.WriteString(q)
				i += end + 2
			case c == '$':
				w.bare = false
				n, err := lexVar(s[i:], &b, expand)
				if err != nil {
					return nil, "", err
				}
				i += n
			case c == '~' && i == start && (i+1 == len(s) || s[i+1] == '/' || blank(s[i+1])):
				w.bare = false
				home, err := variable("HOME", expand)
				if err != nil {
					return nil, "", fmt.Errorf("~: %w", err)
				}
				b.WriteString(home)
				i++
			case bareChar(c):
				b.WriteRune(c)
				i += size
			default:
				return nil, "", fmt.Errorf("%q: quote a word with %s in it", s[start:], strconv.QuoteRune(c))
			}
		}
		w.s = b.String()
		ws = append(ws, w)
	}
}

// lexDouble reads the text of a "..." word in s, after its opening
// quote, into b, and returns the bytes read, the closing quote included.
func lexDouble(s string, b *strings.Builder, expand Expand) (int, error) {
	i := 0
	for i < len(s) {
		switch c, size := utf8.DecodeRuneInString(s[i:]); {
		case c == '"':
			return i + 1, nil
		case c == '\\' && strings.HasPrefix(s[i:], `\$`):
			b.WriteByte('$')
			i += 2
		case c == '\\':
			v, multibyte, tail, err := strconv.UnquoteChar(s[i:], '"')
			if err != nil {
				return 0, fmt.Errorf("%q: invalid escape", s[i:min(i+2, len(s))])
			}
			if v < utf8.RuneSelf || !multibyte {
				b.WriteByte(byte(v))
			} else {
				b.WriteRune(v)
			}
			i = len(s) - len(tail)
		case c == '$':
			n, err := lexVar(s[i:], b, expand)
			if err != nil {
				return 0, err
			}
			i += n
		case !printable(c):
			return 0, fmt.Errorf("unprintable character %s in \"...\": write it as an escape", strconv.QuoteRune(c))
		default:
			b.WriteRune(c)
			i += size
		}
	}
	return 0, errors.New(`" without its closing "`)
}

// lexVar reads the variable at the start of s ($NAME or ${NAME}) and
// writes its value to b; it returns the bytes read.
func lexVar(s string, b *strings.Builder, expand Expand) (int, error) {
	name, n := "", 0
	if strings.HasPrefix(s, "${") {
		end := strings.IndexByte(s, '}')
		if end < 0 {
			return 0, fmt.Errorf("%q: ${ without }", s)
		}
		name, n = s[2:end], end+1
	} else {
		n = 1
		for n < len(s) && (s[n] == '_' || s[n] >= 'A' && s[n] <= 'Z' || s[n] >= 'a' && s[n] <= 'z' || n > 1 && s[n] >= '0' && s[n] <= '9') {
			n++
		}
		name = s[1:n]
	}
	if name == "" {
		return 0, errors.New(`$ without a variable name: write a $ as \$ in "..." or in '...'`)
	}
	v, err := variable(name, expand)
	if err != nil {
		return 0, err
	}
	b.WriteString(v)
	return n, nil
}

func variable(name string, expand Expand) (string, error) {
	if expand == nil {
		return "", fmt.Errorf("$%s: variables are expanded in rule files only", name)
	}
	return expand(name)
}

// printable reports whether c can be written as is in quotes: not a
// control or format character (an escape sequence, a bidi override).
func printable(c rune) bool {
	return c == ' ' || unicode.IsPrint(c)
}

// quote writes s as a word lex reads back: as is when it has only bare
// characters, else in "..." with escapes for ", \, $ and the characters
// that are not printable, and \x for bytes of invalid UTF-8.
func quote(s string) string {
	if s != "" && s != "for" && s[0] != '~' && s[0] != '#' && strings.IndexFunc(s, func(c rune) bool { return !bareChar(c) }) < 0 {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case c == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case c == '"' || c == '\\' || c == '$':
			b.WriteByte('\\')
			b.WriteRune(c)
		case printable(c):
			b.WriteRune(c)
		default:
			q := strconv.QuoteRune(c)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	b.WriteByte('"')
	return b.String()
}
