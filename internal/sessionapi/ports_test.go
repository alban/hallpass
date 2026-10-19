// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestPorts(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := SocketDir()
	if err := ensureSocketDir(dir); err != nil {
		t.Fatal(err)
	}
	got := make(chan []uint16, 4)
	stop, err := WatchPorts(func(p []uint16) { got <- p })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// A process that exited, and files that are not regular.
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "web-"+strconv.Itoa(c.Process.Pid)+".port")
	if err := os.WriteFile(stale, []byte("1111\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "ports")
	if err := os.WriteFile(target, []byte("2222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "web-1.port")); err != nil {
		t.Fatal(err)
	}

	unregister, err := RegisterPorts([]uint16{8080, 7323})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if !slices.Equal(p, []uint16{8080, 7323}) {
			t.Errorf("watched %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("registration not seen")
	}
	if p := ProtectedPorts(); !slices.Equal(p, []uint16{7323, 8080}) {
		t.Errorf("ProtectedPorts() = %v", p)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Errorf("stale port file kept: %v", err)
	}
	unregister()
	if p := ProtectedPorts(); len(p) != 0 {
		t.Errorf("after unregister: %v", p)
	}
}
