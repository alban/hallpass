// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netns

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEnter: the worker runs in the other namespace, this thread stays,
// and Do after Close fails.
func TestEnter(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("not root")
	}
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		t.Skipf("new network namespace: %v", err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	w, err := Enter(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	var inode uint64
	err = w.Do(func() error {
		var st unix.Stat_t
		if err := unix.Stat("/proc/thread-self/ns/net", &st); err != nil {
			return err
		}
		inode = st.Ino
		return nil
	})
	var theirs unix.Stat_t
	if err != nil || unix.Stat(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid), &theirs) != nil || inode != theirs.Ino {
		t.Fatalf("worker in netns %d, want %d: %v", inode, theirs.Ino, err)
	}
	// Ours is not changed.
	var self unix.Stat_t
	if unix.Stat("/proc/thread-self/ns/net", &self); self.Ino == theirs.Ino {
		t.Fatal("this thread moved")
	}
	// A socket made there sees that namespace: only a loopback, besides
	// the fallback tunnels (sit0...) a kernel with them built in adds,
	// down.
	var ifs []net.Interface
	err = w.Do(func() (err error) { ifs, err = net.Interfaces(); return err })
	lo := false
	for _, i := range ifs {
		lo = lo || i.Name == "lo"
		if i.Name != "lo" && i.Flags&net.FlagUp != 0 {
			lo = false
			break
		}
	}
	if err != nil || !lo {
		t.Errorf("interfaces in the new namespace: %v %v", ifs, err)
	}
	w.Close()
	if err := w.Do(func() error { return nil }); err != ErrClosed {
		t.Errorf("Do after Close: %v", err)
	}
}
