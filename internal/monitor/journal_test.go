// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// sendAsync is send from another goroutine: it blocks until a receiver
// takes the notification.
func (f *fakeNotifier) sendAsync(path string) <-chan uint64 {
	c := make(chan uint64, 1)
	go func() { c <- f.mkdir(path) }()
	return c
}

// TestNoHeadOfLine checks that requests waiting for a human do not hold
// the receivers: more waiting threads than receivers, and an allowed
// syscall still goes through.
func TestNoHeadOfLine(t *testing.T) {
	fx := setup(t, nil, false)
	ok := filepath.Join(fx.dir, "ok")
	fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow)}})
	p := filepath.Join(fx.dir, "x")
	var waiting []<-chan uint64
	for range 3 * max(4, runtime.NumCPU()) {
		waiting = append(waiting, fx.f.sendAsync(p))
	}
	req := fx.next(t, opened).Opened
	for _, c := range waiting {
		select {
		case <-c:
		case <-time.After(5 * time.Second):
			t.Fatal("a waiting notification was not received")
		}
	}
	fx.f.expect(t, fx.f.mkdir(ok+"/a"), 0)
	joined := func() int {
		fx.m.mu.Lock()
		defer fx.m.mu.Unlock()
		return len(fx.m.pending[req.ID].waiters)
	}
	for deadline := time.Now().Add(5 * time.Second); joined() < len(waiting); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d joined the request", joined(), len(waiting))
		}
	}
	fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, false}}})
	for i := range waiting {
		select {
		case r := <-fx.f.out:
			if r.errno != int32(unix.EACCES) {
				t.Fatalf("response %+v", r)
			}
		case <-time.After(5 * time.Second):
			pending, _, _ := fx.m.Snapshot()
			t.Fatalf("%d responses of %d; pending %d", i, len(waiting), len(pending))
		}
	}
}

// TestInflightCap checks that the journal caps the notifications in
// flight: at the cap, the next one waits in the kernel.
func TestInflightCap(t *testing.T) {
	fx := setupJournal(t, Config{}, false, seccomp.NewJournal(2))
	ok := filepath.Join(fx.dir, "ok")
	fx.m.Apply(Decision{AddRules: []rules.Rule{tree(ok, rules.Allow)}})
	fx.f.mkdir(filepath.Join(fx.dir, "x"))
	req := fx.next(t, opened).Opened
	fx.f.mkdir(filepath.Join(fx.dir, "y"))
	fx.next(t, opened)
	third := fx.f.sendAsync(ok + "/a")
	fx.f.expectNone(t)
	fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}})
	<-fx.f.out // x
	id := <-third
	fx.f.expect(t, id, 0)
}

// notifAt returns a mkdirat notification of the test process for path.
func notifAt(id uint64, path []byte) seccomp.Notif {
	n := seccomp.Notif{ID: id, PID: uint32(os.Getpid()), Nr: unix.SYS_MKDIRAT}
	n.Args[0] = uint64(procAtFDCWD())
	n.Args[1] = uint64(uintptr(unsafe.Pointer(&path[0])))
	return n
}

// TestReplay checks that a monitor answers the notifications a previous
// one received and journalled, but did not answer.
func TestReplay(t *testing.T) {
	old, err := seccomp.NewMemfdJournal("test", 8)
	if err != nil {
		t.Skip("memfd journal:", err)
	}
	dir := t.TempDir()
	path := append([]byte(filepath.Join(dir, "x")), 0)
	slot, _ := old.Take(nil)
	putNotif(old.Slot(slot), notifAt(42, path))
	// The previous monitor crashes: only another copy of its memfd stays.
	fd, err := unix.Dup(old.FD())
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	j, err := seccomp.OpenJournal(fd)
	if err != nil {
		t.Fatal(err)
	}
	if p := j.Pending(); len(p) != 1 || p[0].Notif.ID != 42 {
		t.Fatalf("pending %+v", p)
	}
	fx := setupJournal(t, Config{}, false, j)
	req := fx.next(t, opened).Opened
	if got := req.Objects[0].Path.Path; got != string(path[:len(path)-1]) {
		t.Fatalf("replayed request for %q", got)
	}
	fx.m.Apply(Decision{Verdicts: []Verdict{{req.ID, true}}})
	fx.f.expect(t, 42, 0)
	runtime.KeepAlive(path)
}

// TestCloseKeepsJournal checks that a request left unanswered by Close
// stays in the journal, for the next monitor.
func TestCloseKeepsJournal(t *testing.T) {
	j, err := seccomp.NewMemfdJournal("test", 8)
	if err != nil {
		t.Skip("memfd journal:", err)
	}
	fd, err := unix.Dup(j.FD())
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	fx := setupJournal(t, Config{}, false, j)
	id := fx.f.mkdir(filepath.Join(fx.dir, "x"))
	fx.next(t, opened)
	fx.m.Close()
	fx.f.expectNone(t)

	mem, err := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mem)
	var ids []uint64
	for i := 0; i+seccomp.SlotSize <= len(mem); i += seccomp.SlotSize {
		if v := *(*uint64)(unsafe.Pointer(&mem[i])); v != 0 {
			ids = append(ids, v)
		}
	}
	if len(ids) != 1 || ids[0] != id {
		t.Fatalf("journalled ids %v, want [%d]", ids, id)
	}
}
