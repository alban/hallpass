// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestBuiltin(t *testing.T) {
	for _, name := range Builtin() {
		p, err := Load("", name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		ph, err := p.Shape.Placeholder()
		if err != nil {
			t.Fatal(err)
		}
		re := fmt.Sprintf("^%s[%s]{%d}$", regexp.QuoteMeta(p.Shape.Prefix), p.Shape.Chars, p.Shape.Length)
		if !regexp.MustCompile(re).MatchString(ph) {
			t.Errorf("%s: placeholder %q does not match %s", name, ph, re)
		}
	}
	gh, err := Load("", "gh")
	if err != nil || !gh.Mask || !slices.Contains(gh.Hosts, "api.github.com") || gh.Env["GH_TOKEN"] != "{placeholder}" || gh.Source.String() != "cmd:gh auth token" ||
		gh.Shape != (Shape{Prefix: "ghp_", Chars: "A-Za-z0-9", Length: 36}) {
		t.Errorf("gh: %+v %v", gh, err)
	}
}

// TestUserProfile: a file of the user's never shadows the built-in
// profile of its name; config:NAME is the file, and only it.
func TestUserProfile(t *testing.T) {
	dir := t.TempDir()
	own := "name = \"gh\" # mine\nhosts = [\"ghe.example.com\"]\nsource = \"env:MY_GHE_TOKEN\"\nmode = \"pass\"\n"
	if err := os.WriteFile(filepath.Join(dir, "gh.toml"), []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	if p, err := Load(dir, "gh"); err != nil || !p.Mask || !slices.Contains(p.Hosts, "api.github.com") {
		t.Errorf("gh, with a gh.toml of the user's: %+v %v", p, err)
	}
	p, err := Load(dir, "config:gh")
	if err != nil || p.Mask || !slices.Equal(p.Hosts, []string{"ghe.example.com"}) || p.Name != "config:gh" {
		t.Errorf("config:gh: %+v %v", p, err)
	}
	if _, err := Load(dir, "nope"); err == nil || !strings.Contains(err.Error(), "built-in: gh") || !strings.Contains(err.Error(), `"config:nope"`) {
		t.Errorf("nope: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "gh.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir, "config:gh"); err == nil || !strings.Contains(err.Error(), `built-in profile is named "gh"`) {
		t.Errorf("config:gh without its file: %v", err)
	}
	for _, bad := range []string{"../x", "config:../x", "config:", "other:gh"} {
		if _, err := Load(dir, bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{
		"name = \"x\"\nsource = \"env:A\"",                                      // no hosts
		"name = \"x\"\nhosts = [\"a\"]",                                         // no source
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nmode = \"leak\"",    // mode
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nscheme = \"sigv4\"", // scheme
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nlength = \"36\"",    // length, a string
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nlength = 8",         // length
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nchars = \"a.z\"",    // chars
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nprefix = \"a b\"",   // prefix
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\ncolor = \"red\"",    // key
		"name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nenv = { \"A B\" = \"x\" }",
		"name = \"x\"\nname = \"y\"",
		"name = x",
	} {
		if p, err := Parse([]byte(s)); err == nil {
			t.Errorf("%q: %+v, no error", s, p)
		}
	}
}

// TestNoToolKnowledge: the proxy knows no tool, only this package does.
func TestNoToolKnowledge(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/alban/hallpass/internal/egress").Output()
	if err != nil {
		t.Skip(err)
	}
	if strings.Contains(string(out), "internal/egress/profiles") {
		t.Error("internal/egress imports internal/egress/profiles")
	}
}

// TestPlaceholderShapes: a backwards range, or too few random bits, is
// refused rather than giving a guessable placeholder (or a panic); a
// profile setting only some of prefix, chars and length gets the
// defaults of the others.
func TestPlaceholderShapes(t *testing.T) {
	for _, bad := range []Shape{{"x", "z-a", 16}, {"x", "a", 16}, {"x", "aaaa", 40}, {"x", "01", 50}, {"x", "a-z", 300}} {
		if p, err := bad.Placeholder(); err == nil {
			t.Errorf("%+v: %q, want an error", bad, p)
		}
	}
	for _, good := range []Shape{DefaultShape, {"ghp_", "A-Za-z0-9", 36}, {"", "01", 96}} {
		if _, err := good.Placeholder(); err != nil {
			t.Errorf("%+v: %v", good, err)
		}
	}
	p, err := Parse([]byte("name = \"x\"\nhosts = [\"a\"]\nsource = \"env:A\"\nprefix = \"\"\nlength = 40 # more\n"))
	if err != nil || p.Shape != (Shape{Prefix: "", Chars: "a-z0-9", Length: 40}) {
		t.Errorf("prefix and length only: %+v %v", p, err)
	}
}
