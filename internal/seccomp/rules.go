// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"fmt"
	"strings"
)

// Kind says what the filter does with a syscall.
type Kind int

const (
	// NotifyIfWrite notifies only when the open flags in FlagsArg carry
	// write intent (O_WRONLY, O_RDWR, O_CREAT, O_TRUNC); otherwise allows.
	NotifyIfWrite Kind = iota
	// Notify always notifies the supervisor.
	Notify
	// Errno fails the syscall with Errno, without notifying.
	Errno
	// ErrnoIfNamespace fails the syscall with Errno when the flags in
	// FlagsArg request a new user or mount namespace; otherwise allows.
	ErrnoIfNamespace
	// NotifyIfSet notifies when the argument FlagsArg (a pointer) is not
	// zero; otherwise allows.
	NotifyIfSet
)

// PathArg locates a (dirfd, path) pair in the syscall arguments. DirFD is the
// argument index of the directory fd, or -1 when the path is relative to the
// cwd (legacy non-*at syscalls).
type PathArg struct {
	DirFD int
	Path  int
}

// Rule describes how one syscall is handled.
type Rule struct {
	Nr       int
	Name     string
	Kind     Kind
	FlagsArg int    // for NotifyIfWrite, ErrnoIfNamespace and NotifyIfSet
	Errno    uint32 // for Errno and ErrnoIfNamespace
	Op       string // operation shown in prompts
	Paths    []PathArg
	// Cat is what --mediate selects the rule by (see Category); 0 for a
	// syscall installed whatever the categories (execve, refused
	// syscalls).
	Cat Category
}

// Category is a set of mediated syscall categories (--mediate).
type Category uint32

const (
	// Write checks the file changes: opens for write, creations,
	// deletions, renames...
	Write Category = 1 << iota
	// Exec checks the programs executed. execve is notified whatever the
	// categories (see commonRules): the monitor checks the program only
	// when Exec is mediated.
	Exec
	// Connect checks the network destinations: connect, and the sends
	// with an address.
	Connect

	// DefaultCategories leaves out Connect until it is stable.
	DefaultCategories = Write | Exec
	AllCategories     = Write | Exec | Connect
)

var categoryNames = []struct {
	c    Category
	name string
}{{Write, "write"}, {Exec, "exec"}, {Connect, "connect"}}

// String lists c as ParseCategories reads it: "write,exec".
func (c Category) String() string {
	var s []string
	for _, n := range categoryNames {
		if c&n.c != 0 {
			s = append(s, n.name)
		}
	}
	return strings.Join(s, ",")
}

// ParseCategories reads a comma-separated list of categories: write,
// exec, connect.
func ParseCategories(s string) (Category, error) {
	var c Category
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		found := false
		for _, n := range categoryNames {
			if n.name == f {
				c, found = c|n.c, true
			}
		}
		if !found {
			return 0, fmt.Errorf("unknown category %q (want write, exec or connect)", f)
		}
	}
	return c, nil
}

// Select returns the rules of rs installed when mediating cats: the
// notified syscalls of the other categories are left out.
func Select(rs []Rule, cats Category) []Rule {
	var out []Rule
	for _, r := range rs {
		if c := r.Category(); c == 0 || c&cats != 0 {
			out = append(out, r)
		}
	}
	return out
}

// Category returns r.Cat, or Write for the file syscalls, which leave it
// unset.
func (r Rule) Category() Category {
	if r.Cat == 0 && len(r.Paths) > 0 && r.Op != "exec" {
		return Write
	}
	return r.Cat
}

// RuleFor returns the rule for syscall nr, if any.
func RuleFor(rules []Rule, nr int32) (Rule, bool) {
	for _, r := range rules {
		if int32(r.Nr) == nr {
			return r, true
		}
	}
	return Rule{}, false
}
