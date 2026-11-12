// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRawSockets(t *testing.T) {
	root := t.TempDir()
	bundle := func(name, config string) string {
		dir := filepath.Join(root, "run", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if config != "" {
			if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return "/run/" + name
	}
	caps := func(bounding string) string {
		return `{"process": {"capabilities": {"bounding": [` + bounding + `], "effective": [` + bounding + `]}}}`
	}
	dropped := bundle("dropped", caps(`"CAP_CHOWN", "CAP_KILL"`))
	defaults := bundle("default", caps(`"CAP_CHOWN", "CAP_NET_RAW"`))
	ambient := bundle("ambient", `{"process": {"capabilities": {"ambient": ["CAP_NET_RAW"]}}}`)
	noCaps := bundle("nocaps", `{"process": {"args": ["sh"]}}`)
	missing := bundle("missing", "")
	bad := bundle("bad", "{")
	big := bundle("big", caps(`"CAP_CHOWN"`)+strings.Repeat(" ", maxConfig))
	dir := bundle("dir", "")
	if err := os.Mkdir(filepath.Join(root, dir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := bundle("link", "")
	if err := os.Symlink(filepath.Join(root, dropped, "config.json"), filepath.Join(root, link, "config.json")); err != nil {
		t.Fatal(err)
	}
	fifo := bundle("fifo", "")
	if err := syscall.Mkfifo(filepath.Join(root, fifo, "config.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Resolved in the root: "/run/dropped" there, not the host's.
	escape := bundle("escape", "")
	if err := os.Symlink("/../../../..", filepath.Join(root, escape, "up")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, bundle string
		raw          bool
	}{
		{"dropped", dropped, false},
		{"containerd's defaults", defaults, true},
		{"ambient", ambient, true},
		{"no capabilities", noCaps, true},
		{"no config", missing, true},
		{"not JSON", bad, true},
		{"too large", big, true},
		{"a directory", dir, true},
		{"a symlink", link, true},
		{"a FIFO", fifo, true},
		{"relative", "run/dropped", true},
		{"symlink kept in the root", escape + "/up" + dropped, false},
	} {
		got := rawSockets(root, c.bundle)
		if (got != "") != c.raw {
			t.Errorf("%s: rawSockets = %q, want raw %v", c.name, got, c.raw)
		}
	}
	if got := rawSockets("", dropped); got == "" {
		t.Error("no host root: want raw")
	}
}
