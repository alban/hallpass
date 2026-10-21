// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import "testing"

func TestCategories(t *testing.T) {
	for in, want := range map[string]Category{
		"write,exec": DefaultCategories, "connect": Connect, " write , connect ": Write | Connect, "": 0,
	} {
		got, err := ParseCategories(in)
		if err != nil || got != want {
			t.Errorf("ParseCategories(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"write,dns", "files", "network"} {
		if _, err := ParseCategories(in); err == nil {
			t.Errorf("unknown category %q accepted", in)
		}
	}
	if s := AllCategories.String(); s != "write,exec,connect" {
		t.Errorf("String = %q", s)
	}
}

func TestSelect(t *testing.T) {
	has := func(rs []Rule, name string) bool {
		for _, r := range rs {
			if r.Name == name {
				return true
			}
		}
		return false
	}
	all := Rules(false)
	none := Select(all, Exec)
	for _, name := range []string{"execve", "execveat", "io_uring_setup", "unshare"} {
		if !has(none, name) {
			t.Errorf("--mediate=exec lost %s", name)
		}
	}
	for _, name := range []string{"openat", "unlinkat", "renameat2", "openat2", "truncate"} {
		if has(none, name) {
			t.Errorf("--mediate=exec kept %s", name)
		}
		if !has(Select(all, Write), name) {
			t.Errorf("--mediate=write lost %s", name)
		}
	}
	for _, name := range []string{"connect", "sendto", "sendmsg", "sendmmsg"} {
		if has(Select(all, DefaultCategories), name) {
			t.Errorf("default categories kept %s", name)
		}
		if !has(Select(all, Connect), name) {
			t.Errorf("--mediate=connect lost %s", name)
		}
	}
}
