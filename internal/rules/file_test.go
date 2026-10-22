// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testVars(name string) (string, error) {
	switch name {
	case "HOME":
		return "/home/me", nil
	case "WORKDIR":
		return "/home/me/src/p", nil
	case "UID":
		return "1000", nil
	}
	return "", fmt.Errorf("$%s: unknown variable", name)
}

func TestParseFile(t *testing.T) {
	text := `# build.rules
allow write ~/.cache/go-build/**
  ask write $WORKDIR/.git/**   # hooks run outside
deny	exec	/usr/bin/curl
allow connect unix:/run/user/${UID}/bus
allow exec @git

allow write "/tmp/a#b"
allow write ~/"My Documents/a#b" # a comment
allow write "$HOME/a b" # $NOPE in a comment
allow write '/x/$y'
group @build make /usr/bin/cc "/opt/my tools/**"
allow exec @build
`
	got, err := ParseFile("build.rules", text, testVars)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range got {
		s := r.Group
		if s == "" {
			s = r.Rule.Spec()
		}
		if r.Members != nil {
			s = fmt.Sprintf("group %s %q", r.Group, r.Members)
		}
		lines = append(lines, fmt.Sprintf("%d %s", r.Line, s))
	}
	want := []string{
		"2 allow write /home/me/.cache/go-build/**",
		"3 ask write /home/me/src/p/.git/**",
		"4 deny exec /usr/bin/curl",
		"5 allow connect unix:/run/user/1000/bus",
		"6 @git",
		`8 allow write "/tmp/a#b"`,
		`9 allow write "/home/me/My Documents/a#b"`,
		`10 allow write "/home/me/a b"`,
		`11 allow write "/x/\$y"`,
		`12 group @build ["make" "/usr/bin/cc" "/opt/my tools/**"]`,
		"13 @build",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	// The rules are those of the same lines given to ParseSpec.
	r, _ := ParseSpec("deny exec /usr/bin/curl", time.Time{})
	if got[2].Rule.Ops != r.Ops || got[2].Rule.Verdict != Deny {
		t.Errorf("line 4: %+v", got[2].Rule)
	}
}

func TestParseFileErrors(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"allow write x", "f:1:"},
		{"\n\nallow write $NOPE/x", "f:3: $NOPE: unknown variable"},
		{"allow write ${HOME", "f:1:"},
		{"allow write /x for 1h", "f:1: a rule file takes no expiry"},
		{"deny exec /usr/bin/curl for 1d", "f:1: a rule file takes no expiry"},
		{"deny exec @shells", "f:1: deny exec @shells: a group can only be allowed"},
		{"maybe write /x", "f:1:"},
		{"allow write $/x", "f:1:"},
		{"allow write /a b", "f:1: allow write: 2 words"},
		{"allow write /a#b", "f:1:"},
		{`allow write "/a`, "f:1:"},
		{"group @x", "f:1: group:"},
		{"group x make", "f:1: group:"},
		{"allow exec @a @b", "f:1:"},
	} {
		_, err := ParseFile("f", c.text, testVars)
		var fe *FileError
		if err == nil || !errors.As(err, &fe) || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%q: %v, want %s...", c.text, err, c.want)
		}
	}
}
