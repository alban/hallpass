// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package seccomp

import (
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SlotSize is the size of a journal slot: one struct seccomp_notif.
const SlotSize = sizeofNotif

// DefaultSlots is the default number of in-flight notifications per
// listener.
const DefaultSlots = 1024

// Journal holds the notifications received from one listener and not yet
// answered, so that another process can answer them after a crash:
// NOTIF_RECV never returns a received notification again. Recv writes
// into a slot, the kernel filling it before the ioctl returns; Release
// clears it after the answer. A slot never crosses a page, and a memfd
// journal is populated and locked when created, so the kernel's copy
// cannot fail half-way.
type Journal struct {
	mem    []byte
	fd     int // the memfd; -1 on the heap
	mapped bool
	slots  int
	free   chan int
	recov  []Pending
}

// Pending is a notification found in a journal when it was opened.
type Pending struct {
	Slot  int
	Notif Notif
}

var pageSize = unix.Getpagesize()

func slotsPerPage() int { return pageSize / SlotSize }

func journalSize(slots int) int {
	return (slots + slotsPerPage() - 1) / slotsPerPage() * pageSize
}

// NewJournal returns a journal of n slots on the heap: for a monitor that
// nothing recovers.
func NewJournal(n int) *Journal {
	if n <= 0 {
		n = DefaultSlots
	}
	return newJournal(make([]byte, journalSize(n)), -1, false, n)
}

// NewMemfdJournal returns a journal of n slots in a sealed memfd, its
// pages populated and locked: allocation failures happen here, not in
// the kernel's copy of a notification.
func NewMemfdJournal(name string, n int) (*Journal, error) {
	if n <= 0 {
		n = DefaultSlots
	}
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	size := journalSize(n)
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("journal: ftruncate: %w", err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("journal: seal: %w", err)
	}
	mem, err := mapJournal(fd, size)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return newJournal(mem, fd, true, n), nil
}

// OpenJournal adopts the memfd of a journal created by NewMemfdJournal,
// e.g. received back after a crash. Pending lists its notifications.
func OpenJournal(fd int) (*Journal, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil {
		return nil, fmt.Errorf("journal: seals: %w", err)
	}
	const want = unix.F_SEAL_SHRINK | unix.F_SEAL_GROW
	size := int(st.Size)
	if seals&want != want || size <= 0 || size%pageSize != 0 {
		return nil, errors.New("journal: not a sealed journal memfd")
	}
	mem, err := mapJournal(fd, size)
	if err != nil {
		return nil, err
	}
	j := newJournal(mem, fd, true, size/pageSize*slotsPerPage())
	return j, nil
}

func mapJournal(fd, size int) ([]byte, error) {
	mem, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("journal: mmap: %w", err)
	}
	// Allocate every page now, reporting a failure (Linux 5.14+; mlock
	// populates the older ones).
	if err := unix.Madvise(mem, unix.MADV_POPULATE_WRITE); err != nil && err != unix.EINVAL {
		unix.Munmap(mem)
		return nil, fmt.Errorf("journal: populate: %w", err)
	}
	if err := unix.Mlock(mem); err != nil {
		unix.Munmap(mem)
		return nil, fmt.Errorf("journal: mlock: %w", err)
	}
	return mem, nil
}

func newJournal(mem []byte, fd int, mapped bool, n int) *Journal {
	j := &Journal{mem: mem, fd: fd, mapped: mapped, slots: n, free: make(chan int, n)}
	seen := map[uint64]bool{}
	for i := range n {
		s := j.Slot(i)
		id := *(*uint64)(unsafe.Pointer(&s[0]))
		if id == 0 {
			j.free <- i
			continue
		}
		if seen[id] {
			// Cannot happen (a receive writes all or nothing, and
			// clears nothing): keep the first.
			j.Release(i)
			continue
		}
		seen[id] = true
		j.recov = append(j.recov, Pending{Slot: i, Notif: parseNotif(s)})
	}
	return j
}

// Len is the number of slots.
func (j *Journal) Len() int { return j.slots }

// FD returns the memfd, or -1 for a journal on the heap.
func (j *Journal) FD() int { return j.fd }

// Pending returns the notifications the journal held when it was opened.
// Their slots stay taken until released.
func (j *Journal) Pending() []Pending { return j.recov }

// Slot returns slot i.
func (j *Journal) Slot(i int) []byte {
	off := i/slotsPerPage()*pageSize + i%slotsPerPage()*SlotSize
	return j.mem[off : off+SlotSize : off+SlotSize]
}

// Take returns a free slot, zeroed, waiting for one; false once done is
// closed.
func (j *Journal) Take(done <-chan struct{}) (int, bool) {
	select {
	case i := <-j.free:
		clear(j.Slot(i))
		return i, true
	case <-done:
		return 0, false
	}
}

// Release clears slot i, with one atomic store of its id, and frees it.
func (j *Journal) Release(i int) {
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&j.Slot(i)[0])), 0)
	j.free <- i
}

// Close unmaps the journal and closes its memfd. No slot may be in use.
func (j *Journal) Close() error {
	var err error
	if j.mapped {
		err = unix.Munmap(j.mem)
	}
	if j.fd >= 0 {
		err = errors.Join(err, unix.Close(j.fd))
	}
	j.mem = nil
	return err
}
