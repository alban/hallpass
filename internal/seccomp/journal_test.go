// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func uintptrOf(b []byte) uintptr { return uintptr(unsafe.Pointer(&b[0])) }

func TestJournalLayout(t *testing.T) {
	j := NewJournal(200)
	per := pageSize / SlotSize
	for i := range j.Len() {
		s := j.Slot(i)
		off := int(uintptrOf(s) - uintptrOf(j.mem))
		if off/pageSize != (off+SlotSize-1)/pageSize {
			t.Fatalf("slot %d crosses a page", i)
		}
		if off%8 != 0 {
			t.Fatalf("slot %d not aligned", i)
		}
	}
	if want := (200 + per - 1) / per * pageSize; len(j.mem) != want {
		t.Fatalf("size %d, want %d", len(j.mem), want)
	}
}

func TestJournalReopen(t *testing.T) {
	j, err := NewMemfdJournal("test", 8)
	if err != nil {
		t.Skip("memfd journal:", err)
	}
	put := func(i int, id uint64) {
		binary.LittleEndian.PutUint64(j.Slot(i)[0:], id)
		binary.LittleEndian.PutUint32(j.Slot(i)[16:], 83)
	}
	a, _ := j.Take(nil)
	b, _ := j.Take(nil)
	c, _ := j.Take(nil)
	put(a, 7)
	put(b, 9)
	put(c, 7) // a duplicate: cannot happen, keep one
	d, _ := j.Take(nil)
	put(d, 11)
	j.Release(d) // answered

	fd, err := unix.Dup(j.FD())
	if err != nil {
		t.Fatal(err)
	}
	j.Close()
	r, err := OpenJournal(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p := r.Pending()
	if len(p) != 2 || p[0].Notif.ID != 7 || p[1].Notif.ID != 9 || p[0].Notif.Nr != 83 {
		t.Fatalf("pending %+v", p)
	}
	if free := len(r.free); free != r.Len()-2 {
		t.Fatalf("%d free slots, want %d", free, r.Len()-2)
	}
	// Take zeroes the slot it returns.
	i, _ := r.Take(nil)
	for _, v := range r.Slot(i) {
		if v != 0 {
			t.Fatalf("slot %d not zeroed", i)
		}
	}
}

func TestOpenJournalRejects(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "j")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Truncate(int64(pageSize))
	if _, err := OpenJournal(int(f.Fd())); err == nil {
		t.Fatal("a regular file opened as a journal")
	}
}
