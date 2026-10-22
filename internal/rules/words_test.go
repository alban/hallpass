// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

func TestLex(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []string // a bare word starts with +
		comment string
		err     string
	}{
		{in: "", want: nil},
		{in: "  \t ", want: nil},
		{in: "a b\tc", want: []string{"+a", "+b", "+c"}},
		{in: `"a b" c`, want: []string{"a b", "+c"}},
		{in: `/x/"a b"/**`, want: []string{"/x/a b/**"}},
		{in: `'a $b \n'`, want: []string{`a $b \n`}},
		{in: `"a\"b\\c\$d\t\x41\u00e9"`, want: []string{"a\"b\\c$d\tAé"}},
		{in: `""`, want: []string{""}},
		{in: `a # b "c`, want: []string{"+a"}, comment: `b "c`},
		{in: "# all", comment: "all"},
		{in: "a#b", err: "quote a word with '#'"},
		{in: `"a#b"`, want: []string{"a#b"}},
		{in: "$HOME/x ${UID}", want: []string{"/home/me/x", "1000"}},
		{in: `"$HOME/a b"`, want: []string{"/home/me/a b"}},
		{in: "~ ~/x a~", want: []string{"/home/me", "/home/me/x", "+a~"}},
		{in: "~x", want: []string{"+~x"}},
		{in: "$NOPE", err: "$NOPE: unknown variable"},
		{in: "${HOME", err: "?"},
		{in: `"a`, err: "?"},
		{in: `'a`, err: "?"},
		{in: `"\q"`, err: "?"},
		{in: "a,b", err: "?"},
		{in: "a\x1bb", err: "?"},
		{in: "\"a\x1bb\"", err: "?"},
		{in: "\"a\u202eb\"", err: "?"},
		{in: "a\xffb", err: "?"},
		{in: `"\xff"`, want: []string{"\xff"}},
	} {
		ws, comment, err := lex(tc.in, testVars)
		if tc.err != "" {
			if err == nil || tc.err != "?" && !strings.Contains(err.Error(), tc.err) {
				t.Errorf("lex(%q) = %v, %v, want error %q", tc.in, ws, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("lex(%q): %v", tc.in, err)
			continue
		}
		var got []string
		for _, w := range ws {
			if w.bare {
				got = append(got, "+"+w.s)
			} else {
				got = append(got, w.s)
			}
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") || len(got) != len(tc.want) || comment != tc.comment {
			t.Errorf("lex(%q) = %q, %q, want %q, %q", tc.in, got, comment, tc.want, tc.comment)
		}
	}
	if _, _, err := lex("$HOME", nil); err == nil {
		t.Errorf("lex($HOME) without variables: no error")
	}
}

func TestQuote(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/usr/bin/git", "/usr/bin/git"},
		{"/home/u/src/**", "/home/u/src/**"},
		{"tcp:[2001:db8::1]:22", "tcp:[2001:db8::1]:22"},
		{"/home/u/café", "/home/u/café"},
		{"", `""`},
		{"for", `"for"`},
		{"~/x", `"~/x"`},
		{"#x", `"#x"`},
		{"/a b", `"/a b"`},
		{`/a"b\c$d`, `"/a\"b\\c\$d"`},
		{"/a,b", `"/a,b"`},
		{"/a'b", `"/a'b"`},
		{"/x\x1b[2J", `"/x\x1b[2J"`},
		{"/x\u202e", `"/x\u202e"`},
		{"/x\xff", `"/x\xff"`},
		{"/x\n", `"/x\n"`},
	} {
		if got := quote(tc.in); got != tc.want {
			t.Errorf("quote(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

// FuzzQuote checks that lex reads quote's words back.
func FuzzQuote(f *testing.F) {
	for _, s := range []string{"", "/a b", "for", "~", "#", "$x", `"'\`, "\x00\x1b\u202e\xff", "a#b", "日本"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		q := quote(s)
		ws, comment, err := lex(q+" x", nil)
		if err != nil || len(ws) != 2 || ws[0].s != s || ws[0].bare && s == "for" || comment != "" {
			t.Fatalf("quote(%q) = %s, read back as %v, %q, %v", s, q, ws, comment, err)
		}
	})
}
