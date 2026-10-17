// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package fdstore

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func start(t *testing.T, uid int) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run", "fd-store.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{UID: uid, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	go s.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	return s, path
}

func dial(t *testing.T, path string) *Client {
	t.Helper()
	c, err := Dial(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// pipe returns a pipe whose write end only the store will hold.
func pipe(t *testing.T) (r *os.File, w int) {
	t.Helper()
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	r = os.NewFile(uintptr(p[0]), "r")
	t.Cleanup(func() { r.Close() })
	return r, p[1]
}

// eof reports whether r's writers are all closed.
func eof(t *testing.T, r *os.File) bool {
	t.Helper()
	fds := []unix.PollFd{{Fd: int32(r.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 200)
	if err != nil {
		t.Fatal(err)
	}
	return n == 1 && fds[0].Revents&unix.POLLHUP != 0
}

func TestPutListDelete(t *testing.T) {
	s, path := start(t, os.Getuid())
	c := dial(t, path)
	if !c.Alive() {
		t.Fatal("new connection not alive")
	}

	r1, w1 := pipe(t)
	r2, w2 := pipe(t)
	if err := c.Put("a", []int{w1, w2}); err != nil {
		t.Fatal(err)
	}
	unix.Close(w1)
	unix.Close(w2)
	if eof(t, r1) {
		t.Fatal("the store closed a stored fd")
	}

	// A new client, as after a crash, gets working copies.
	es, err := dial(t, path).List()
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || es[0].Key != "a" || len(es[0].FDs) != 2 {
		t.Fatalf("entries %+v", es)
	}
	if _, err := unix.Write(es[0].FDs[1], []byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := r2.Read(b); err != nil || b[0] != 'x' {
		t.Fatalf("read %q, %v", b, err)
	}
	CloseAll(es[0].FDs)

	// Replacing closes the old fds.
	r3, w3 := pipe(t)
	if err := c.Put("a", []int{w3}); err != nil {
		t.Fatal(err)
	}
	unix.Close(w3)
	if !eof(t, r1) || !eof(t, r2) {
		t.Fatal("replaced fds still open")
	}
	if eof(t, r3) {
		t.Fatal("new fd closed")
	}
	if err := c.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if !eof(t, r3) {
		t.Fatal("deleted fd still open")
	}
	if s.Len() != 0 {
		t.Fatalf("%d entries left", s.Len())
	}
	if err := c.Delete("missing"); err != nil {
		t.Fatal(err)
	}
}

func TestManyFDs(t *testing.T) {
	_, path := start(t, os.Getuid())
	c := dial(t, path)
	fds := make([]int, MaxFDs)
	for i := range fds {
		_, fds[i] = pipe(t)
	}
	defer CloseAll(fds)
	if err := c.Put("big", fds); err != nil {
		t.Fatal(err)
	}
	es, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(es) != 1 || len(es[0].FDs) != MaxFDs {
		t.Fatalf("got %d entries", len(es))
	}
	CloseAll(es[0].FDs)
	if err := c.Put("big", append(fds, fds[0])); err == nil {
		t.Fatal("put of too many fds succeeded")
	}
}

func TestRefused(t *testing.T) {
	_, path := start(t, os.Getuid()+1)
	c := dial(t, path)
	for c.Alive() {
		time.Sleep(10 * time.Millisecond)
	}
	_, w := pipe(t)
	defer unix.Close(w)
	if err := c.Put("a", []int{w}); !errors.Is(err, ErrClosed) {
		t.Fatalf("put by another uid: %v", err)
	}
}

func TestBadRequest(t *testing.T) {
	_, path := start(t, os.Getuid())
	c := dial(t, path)
	_, w := pipe(t)
	defer unix.Close(w)
	var re *RequestError
	if err := c.Put("", []int{w}); !errors.As(err, &re) {
		t.Fatalf("put without key: %v", err)
	}
	// The connection stays usable.
	if _, err := c.List(); err != nil {
		t.Fatal(err)
	}
}
