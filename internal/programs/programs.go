// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package programs names groups of programs (@shells, @coreutils...) and
// finds programs as the sandbox does: by name in $PATH, symlinks resolved,
// on the host or in a container's root. Exec rules match the resolved
// paths.
package programs

import (
	"fmt"
	"os"
	"path"
	"slices"
	"strings"
)

// Group is a named set of programs, resolved: Members are absolute paths
// without symlinks, without duplicates, in the order of the group's
// definition.
type Group struct {
	Name    string // e.g. "@coreutils"
	Members []string
}

// String describes g for people, e.g. "@coreutils (cat, ls, cp, … 104
// programs)".
func (g Group) String() string {
	n := len(g.Members)
	if n == 0 {
		return g.Name + " (no programs here)"
	}
	names := make([]string, 0, 3)
	for _, m := range g.Members {
		if len(names) == 3 {
			break
		}
		// git is both /usr/bin/git and /usr/lib/git-core/git.
		if b := path.Base(m); !slices.Contains(names, b) {
			names = append(names, b)
		}
	}
	s := strings.Join(names, ", ")
	switch {
	case n > len(names):
		s += fmt.Sprintf(", … %d programs", n)
	case n > 1:
		s += fmt.Sprintf(": %d programs", n)
	}
	return g.Name + " (" + s + ")"
}

// Def defines a group. A member is a name looked up in $PATH, an absolute
// path, DIR/* for every program directly in DIR, or DIR/** for every
// program below DIR (resolved below DIR too). Applets also adds the
// programs of $PATH that are hard links to the first member: the applets
// of a multi-call binary.
type Def struct {
	Name    string
	Members []string
	Applets bool
}

// builtin are the built-in groups. They are starting points, to tune with
// real agents; a group is offered in prompts for its programs, and
// allowed by --allow-exec=@name or a HallpassPolicy's allowExec. A
// policy's groups add to them or replace them (Merge).
var builtin = []Def{
	{Name: "@shells", Members: []string{"sh", "bash", "dash", "zsh", "ash", "env"}},
	{Name: "@coreutils", Members: []string{
		"cat", "ls", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln", "chmod",
		"chown", "chgrp", "head", "tail", "wc", "sort", "uniq", "cut", "tr", "tee",
		"echo", "printf", "pwd", "basename", "dirname", "readlink", "realpath",
		"stat", "du", "df", "date", "env", "id", "whoami", "groups", "uname",
		"nproc", "seq", "expr", "test", "[", "true", "false", "sleep", "yes",
		"printenv", "mktemp", "install", "dd", "sync", "truncate", "split",
		"csplit", "join", "paste", "comm", "fold", "fmt", "nl", "od", "base32",
		"base64", "basenc", "md5sum", "sha1sum", "sha224sum", "sha256sum",
		"sha384sum", "sha512sum", "b2sum", "cksum", "sum", "shuf", "tac",
		"expand", "unexpand", "numfmt", "factor", "link", "unlink", "mkfifo",
		"mknod", "shred", "timeout", "nice", "nohup", "stdbuf", "tty", "stty",
		"dircolors", "dir", "vdir", "logname", "users", "who", "pinky", "hostid",
		"arch", "pathchk", "ptx", "tsort", "pr", "chroot", "chcon", "runcon",
	}},
	{Name: "@search", Members: []string{
		"grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "xargs", "locate",
		"fd", "fdfind", "sed", "awk", "gawk", "mawk", "diff", "cmp", "file",
		"tree", "less", "more", "which", "jq",
	}},
	// git runs its helpers (git-remote-https, git-upload-pack...) from its
	// exec path.
	{Name: "@git", Members: []string{"git", "/usr/lib/git-core/*", "/usr/libexec/git-core/*"}},
	// Symlinked applets resolve to busybox itself: allowing one allows
	// all (telling them apart needs argv[0]).
	{Name: "@busybox", Members: []string{"busybox"}, Applets: true},
}

// Names returns the names of the built-in groups.
func Names() []string {
	out := make([]string, len(builtin))
	for i, d := range builtin {
		out[i] = d.Name
	}
	return out
}

// Implicit are the groups a workstation session allows without asking,
// but for --no-implicit: what an agent runs all the time.
func Implicit() []string {
	return []string{"@shells", "@coreutils", "@search", "@git"}
}

// Builtin returns the built-in groups.
func Builtin() []Def {
	return Merge(nil)
}

// ValidName reports whether name can name a group: "@", a lowercase
// letter, then lowercase letters, digits or '-', 32 bytes at most.
func ValidName(name string) bool {
	if len(name) < 2 || len(name) > 32 || name[0] != '@' || name[1] < 'a' || name[1] > 'z' {
		return false
	}
	for _, c := range []byte(name[2:]) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// Merge returns the built-in groups with user's: a user group replaces
// the built-in group of the same name, in its place; the others follow,
// in the order given.
func Merge(user []Def) []Def {
	out := make([]Def, 0, len(builtin)+len(user))
	for _, d := range builtin {
		if i := slices.IndexFunc(user, func(u Def) bool { return u.Name == d.Name }); i >= 0 {
			d = user[i]
		}
		d.Members = slices.Clone(d.Members)
		out = append(out, d)
	}
	for _, u := range user {
		if !slices.ContainsFunc(out, func(d Def) bool { return d.Name == u.Name }) {
			u.Members = slices.Clone(u.Members)
			out = append(out, u)
		}
	}
	return out
}

// Finder finds programs in a root directory, as processes there do.
type Finder struct {
	// Root is the directory the paths are in, "" for the host's root,
	// e.g. /proc/PID/root for a container's.
	Root string
	// Path is the $PATH of the lookups.
	Path string
	// Resolve resolves the symlinks of absolute path p inside Root; nil:
	// the paths are not resolved.
	Resolve func(p string) (string, error)
}

// Look returns the resolved path of program name: looked up in Path
// without a slash, as is with one (absolute only).
func (f Finder) Look(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if strings.Contains(name, "/") {
		return f.program(name)
	}
	for _, dir := range strings.Split(f.Path, ":") {
		if !path.IsAbs(dir) {
			continue
		}
		if p, ok := f.program(path.Join(dir, name)); ok {
			return p, true
		}
	}
	return "", false
}

// program resolves absolute path p, if it is an executable file.
func (f Finder) program(p string) (string, bool) {
	if !path.IsAbs(p) {
		return "", false
	}
	if f.Resolve != nil {
		r, err := f.Resolve(p)
		if err != nil {
			return "", false
		}
		p = r
	}
	st, err := os.Stat(f.Root + p)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return "", false
	}
	return p, true
}

// maxMembers bounds a group, against a DIR/** over a large tree.
const maxMembers = 4096

// Groups returns groups defs resolved: members not found are left out.
func (f Finder) Groups(defs []Def) []Group {
	out := make([]Group, 0, len(defs))
	for _, d := range defs {
		g := Group{Name: d.Name}
		seen := map[string]bool{}
		add := func(p string) {
			if !seen[p] && len(g.Members) < maxMembers {
				seen[p] = true
				g.Members = append(g.Members, p)
			}
		}
		for _, m := range d.Members {
			if dir, ok := strings.CutSuffix(m, "/**"); ok {
				for _, p := range f.tree(dir) {
					add(p)
				}
				continue
			}
			if dir, ok := strings.CutSuffix(m, "/*"); ok {
				for _, p := range f.dir(dir) {
					add(p)
				}
				continue
			}
			if p, ok := f.Look(m); ok {
				add(p)
			}
		}
		if d.Applets && len(g.Members) > 0 {
			for _, p := range f.links(g.Members[0]) {
				add(p)
			}
		}
		out = append(out, g)
	}
	return out
}

// dir returns the programs directly in dir.
func (f Finder) dir(dir string) []string {
	dir, ok := f.resolveDir(dir)
	if !ok {
		return nil
	}
	ents, err := os.ReadDir(f.Root + dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if p, ok := f.program(path.Join(dir, e.Name())); ok {
			out = append(out, p)
		}
	}
	return out
}

// tree returns the programs below dir, at most maxMembers, whose resolved
// path is below dir too: like a DIR/** exec rule, which matches resolved
// paths. Subdirectories are not followed through symlinks.
func (f Finder) tree(dir string) []string {
	if dir == "" {
		dir = "/"
	}
	dir, ok := f.resolveDir(dir)
	if !ok {
		return nil
	}
	var out []string
	var walk func(d string, depth int)
	walk = func(d string, depth int) {
		ents, err := os.ReadDir(f.Root + d)
		if err != nil {
			return
		}
		for _, e := range ents {
			if len(out) >= maxMembers {
				return
			}
			p := path.Join(d, e.Name())
			if e.IsDir() {
				if depth < 16 {
					walk(p, depth+1)
				}
				continue
			}
			if r, ok := f.program(p); ok && (dir == "/" || strings.HasPrefix(r, dir+"/")) {
				out = append(out, r)
			}
		}
	}
	walk(dir, 0)
	return out
}

// resolveDir resolves absolute directory dir inside Root, so that listing
// it never follows a symlink out of Root.
func (f Finder) resolveDir(dir string) (string, bool) {
	if !path.IsAbs(dir) {
		return "", false
	}
	if f.Resolve == nil {
		return dir, true
	}
	r, err := f.Resolve(dir)
	return r, err == nil
}

// links returns the files of Path's directories that are hard links to
// program p (Lstat: a symlink resolves to p itself, and would be followed
// outside Root).
func (f Finder) links(p string) []string {
	want, err := os.Lstat(f.Root + p)
	if err != nil {
		return nil
	}
	var out []string
	for _, dir := range strings.Split(f.Path, ":") {
		dir, ok := f.resolveDir(dir)
		if !ok {
			continue
		}
		ents, err := os.ReadDir(f.Root + dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !e.Type().IsRegular() {
				continue
			}
			st, err := os.Lstat(f.Root + path.Join(dir, e.Name()))
			if err != nil || !os.SameFile(want, st) {
				continue
			}
			if r, ok := f.program(path.Join(dir, e.Name())); ok {
				out = append(out, r)
			}
		}
	}
	return out
}
