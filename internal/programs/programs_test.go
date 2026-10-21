// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package programs

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestGroups(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"busybox", "dash", "cat", "notexec"} {
		mode := os.FileMode(0o755)
		if n == "notexec" {
			mode = 0o644
		}
		if err := os.WriteFile(filepath.Join(bin, n), []byte(n), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range [][2]string{{"dash", "sh"}, {"busybox", "wget"}} {
		if err := os.Symlink(l[0], filepath.Join(bin, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	// A hard-linked applet.
	if err := os.Link(filepath.Join(bin, "busybox"), filepath.Join(bin, "ls")); err != nil {
		t.Fatal(err)
	}
	f := Finder{Path: "relative:" + bin, Resolve: filepath.EvalSymlinks}
	if p, ok := f.Look("sh"); !ok || p != bin+"/dash" {
		t.Errorf("Look(sh) = %q, %v", p, ok)
	}
	for _, n := range []string{"notexec", "missing", ""} {
		if p, ok := f.Look(n); ok {
			t.Errorf("Look(%q) = %q", n, p)
		}
	}
	got := map[string][]string{}
	for _, g := range f.Groups(Builtin()) {
		got[g.Name] = g.Members
	}
	for name, want := range map[string][]string{
		"@shells":    {bin + "/dash"},
		"@coreutils": {bin + "/cat", bin + "/ls"},
		"@search":    nil,
		"@busybox":   {bin + "/busybox", bin + "/ls"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: got %v, want %v", name, got[name], want)
		}
	}
}

// TestGroupsListing: Groups lists the $PATH directories instead of trying
// every name in every directory, and finds what Look finds: the first
// executable in $PATH order, missing and non-directory entries skipped.
func TestGroupsListing(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first, bin := filepath.Join(dir, "first"), filepath.Join(dir, "bin")
	for _, d := range []string{first, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, mode := range map[string]os.FileMode{
		"first/cat": 0o644, "bin/cat": 0o755, "bin/dash": 0o755, "file": 0o755,
	} {
		if err := os.WriteFile(filepath.Join(dir, p), nil, mode); err != nil {
			t.Fatal(err)
		}
	}
	resolves := 0
	f := Finder{
		Path: strings.Join([]string{dir + "/missing", dir + "/file", first, bin}, ":"),
		Resolve: func(p string) (string, error) {
			resolves++
			return filepath.EvalSymlinks(p)
		},
	}
	// Groups of names only: not @git's absolute directories.
	defs := slices.DeleteFunc(Builtin(), func(d Def) bool { return d.Name == "@git" })
	gs := f.Groups(defs)
	// 4 listings and the 3 names found (cat twice), not one per name and
	// directory (about 4 × 250).
	if resolves != 7 {
		t.Errorf("%d resolves, want 7", resolves)
	}
	got := map[string][]string{}
	for _, g := range gs {
		got[g.Name] = g.Members
		for _, m := range g.Members {
			if l, ok := f.Look(path.Base(m)); !ok || l != m {
				t.Errorf("%s: Look(%s) = %q, %v", g.Name, path.Base(m), l, ok)
			}
		}
	}
	for name, want := range map[string][]string{
		"@shells":    {bin + "/dash"},
		"@coreutils": {bin + "/cat"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: got %v, want %v", name, got[name], want)
		}
	}
}

// TestGroupsUnlisted: a $PATH directory that can be searched but not
// read is still searched.
func TestGroupsUnlisted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any directory")
	}
	bin := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "dash"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(bin, 0o755) })
	gs := Finder{Path: bin}.Groups(Builtin())
	if gs[0].Name != "@shells" || !slices.Equal(gs[0].Members, []string{bin + "/dash"}) {
		t.Errorf("got %v", gs[0])
	}
}

// TestUserGroups: a user group replaces the built-in group of its name or
// adds one; DIR/** keeps the programs that resolve below DIR.
func TestUserGroups(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tools := filepath.Join(dir, "tools")
	if err := os.MkdirAll(filepath.Join(tools, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"tools/a", "tools/sub/b", "outside", "dash"} {
		if err := os.WriteFile(filepath.Join(dir, p), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Resolves out of the tree: left out of tools/**.
	if err := os.Symlink(filepath.Join(dir, "outside"), filepath.Join(tools, "link")); err != nil {
		t.Fatal(err)
	}
	defs := Merge([]Def{
		{Name: "@tools", Members: []string{tools + "/**"}},
		{Name: "@shells", Members: []string{dir + "/dash"}},
	})
	if n := len(defs); n != len(Builtin())+1 || defs[0].Name != "@shells" || defs[n-1].Name != "@tools" {
		t.Fatalf("Merge: %v", defs)
	}
	f := Finder{Path: dir, Resolve: filepath.EvalSymlinks}
	got := map[string][]string{}
	for _, g := range f.Groups(defs) {
		got[g.Name] = g.Members
	}
	for name, want := range map[string][]string{
		"@tools":  {tools + "/a", tools + "/sub/b"},
		"@shells": {dir + "/dash"},
	} {
		if !slices.Equal(got[name], want) {
			t.Errorf("%s: got %v, want %v", name, got[name], want)
		}
	}
	if len(Builtin()[0].Members) < 2 {
		t.Error("Merge changed the built-in groups")
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"@git": true, "@my-tools2": true, "@": false, "git": false, "@Git": false,
		"@2go": false, "@a b": false, "@a/b": false, "@" + strings.Repeat("a", 32): false,
	} {
		if ValidName(name) != want {
			t.Errorf("ValidName(%q) = %v", name, !want)
		}
	}
}

func TestGroupString(t *testing.T) {
	for _, c := range []struct {
		g    Group
		want string
	}{
		{Group{"@git", nil}, "@git (no programs here)"},
		{Group{"@git", []string{"/usr/bin/git"}}, "@git (git)"},
		{Group{"@shells", []string{"/bin/sh", "/bin/bash"}}, "@shells (sh, bash: 2 programs)"},
		{Group{"@coreutils", []string{"/a/cat", "/a/ls", "/a/cp", "/a/mv"}}, "@coreutils (cat, ls, cp, … 4 programs)"},
		{Group{"@git", []string{"/usr/bin/git", "/g/git", "/g/git-daemon"}}, "@git (git, git-daemon, … 3 programs)"},
		{Group{"@git", []string{"/usr/bin/git", "/g/git"}}, "@git (git, … 2 programs)"},
	} {
		if got := c.g.String(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}
