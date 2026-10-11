// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hallpass")
	c, err := Load(dir)
	if err != nil || c.Get("escalate") != "" {
		t.Fatalf("missing file: %v, %q", err, c.Get("escalate"))
	}
	if err := c.Set("escalate", "sudo"); err != nil {
		t.Fatal(err)
	}
	if err := c.Set("other", "x = y"); err != nil {
		t.Fatal(err)
	}
	c, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Get("escalate") != "sudo" || c.Get("other") != "x = y" {
		t.Errorf("got %v", c.values)
	}
	if fi, err := os.Stat(c.Path()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", fi.Mode(), err)
	}
}

func TestBadLine(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("# c\n\nescalate sudo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("bad line accepted")
	}
}

func TestDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/x/cfg")
	if d, _ := Dir(); d != "/x/cfg/hallpass" {
		t.Errorf("got %s", d)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("HOME", "/home/u")
	if d, _ := Dir(); d != "/home/u/.config/hallpass" {
		t.Errorf("got %s", d)
	}
}
