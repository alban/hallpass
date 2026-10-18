// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	secompSetModeFilter = 1
	filterFlagNewLister = unix.SECCOMP_FILTER_FLAG_NEW_LISTENER
	// Linux 5.19+.
	filterFlagWaitKillableRecv = unix.SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV

	// ioctl numbers for the notify fd. RECV/SEND are not exported by
	// x/sys/unix; the values are identical on arm64 and amd64 (same struct
	// sizes). RECV=_IOWR('!',0,seccomp_notif[80]), SEND=_IOWR('!',1,resp[24]).
	ioctlNotifRecv = 0xc0502100
	ioctlNotifSend = 0xc0182101
	ioctlIDValid   = unix.SECCOMP_IOCTL_NOTIF_ID_VALID

	userNotifFlagContinue = 1 // SECCOMP_USER_NOTIF_FLAG_CONTINUE

	sizeofNotif = 80
	sizeofResp  = 24
)

// Notif is a decoded SECCOMP_IOCTL_NOTIF_RECV result.
type Notif struct {
	ID   uint64
	PID  uint32
	Nr   int32
	Arch uint32
	Args [6]uint64
}

func parseNotif(b []byte) Notif {
	var n Notif
	n.ID = binary.LittleEndian.Uint64(b[0:])
	n.PID = binary.LittleEndian.Uint32(b[8:])
	n.Nr = int32(binary.LittleEndian.Uint32(b[16:]))
	n.Arch = binary.LittleEndian.Uint32(b[20:])
	for i := 0; i < 6; i++ {
		n.Args[i] = binary.LittleEndian.Uint64(b[32+i*8:])
	}
	return n
}

// Listener wraps a seccomp user-notification file descriptor.
type Listener struct {
	fd int
}

// NewListener adopts an existing notify fd (e.g. received over SCM_RIGHTS).
//
// It asks the kernel (Linux 6.6+) to wake up the receiver, then the
// target, on the waker's CPU: each mediated syscall is a ping-pong
// between the two, and a cross-CPU wakeup each way costs more than
// deciding. Older kernels reject the flag; this is only slower.
func NewListener(fd int) *Listener {
	// The flag is passed by value, not by pointer.
	_ = unix.IoctlSetInt(fd, unix.SECCOMP_IOCTL_NOTIF_SET_FLAGS, unix.SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP)
	return &Listener{fd: fd}
}

// FD returns the underlying file descriptor.
func (l *Listener) FD() int { return l.fd }

// Close closes the listener fd.
func (l *Listener) Close() error { return unix.Close(l.fd) }

// Recv blocks until the next syscall is intercepted. The kernel writes
// the notification into slot (SlotSize bytes, e.g. a Journal slot).
func (l *Listener) Recv(slot []byte) (Notif, error) {
	if len(slot) < sizeofNotif {
		return Notif{}, fmt.Errorf("NOTIF_RECV: slot of %d bytes", len(slot))
	}
	for {
		err := ioctlPtr(l.fd, ioctlNotifRecv, unsafe.Pointer(&slot[0]))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return Notif{}, fmt.Errorf("NOTIF_RECV: %w", err)
		}
		return parseNotif(slot), nil
	}
}

// IDValid reports whether the notification is still live (the target is still
// blocked and the pid has not been reused). Call it after reading target
// memory to close the TOCTOU window.
func (l *Listener) IDValid(id uint64) bool {
	v := id
	return ioctlPtr(l.fd, ioctlIDValid, unsafe.Pointer(&v)) == nil
}

// Continue lets the syscall proceed unmodified. NOTE: this reopens the classic
// seccomp-notify TOCTOU gap and is only safe for paths we do not security-gate.
func (l *Listener) Continue(id uint64) error {
	return l.send(id, 0, 0, userNotifFlagContinue)
}

// Deny fails the syscall with errno (a positive value such as EACCES).
func (l *Listener) Deny(id uint64, errno int32) error {
	// The kernel returns resp.error as is (syscall_set_return_value), so it
	// must be negative; a positive value would look like a success, e.g. a
	// file descriptor for openat.
	return l.send(id, 0, -errno, 0)
}

func (l *Listener) send(id uint64, val int64, errno int32, flags uint32) error {
	buf := make([]byte, sizeofResp)
	binary.LittleEndian.PutUint64(buf[0:], id)
	binary.LittleEndian.PutUint64(buf[8:], uint64(val))
	binary.LittleEndian.PutUint32(buf[16:], uint32(errno))
	binary.LittleEndian.PutUint32(buf[20:], flags)
	err := ioctlPtr(l.fd, ioctlNotifSend, unsafe.Pointer(&buf[0]))
	if err == unix.ENOENT {
		// Target was killed or the syscall was interrupted; not our problem.
		return nil
	}
	return err
}

// Install builds the filter from rules, enables NO_NEW_PRIVS and
// loads the filter on the calling OS thread, returning the listener fd. The
// caller MUST have locked the OS thread and must execve from the same thread so
// the filter survives (execve collapses the process to the calling thread).
func Install(rules []Rule) (int, error) {
	if !threadLocked {
		return -1, fmt.Errorf("Install must run on a locked OS thread")
	}
	prog, err := buildFilter(auditArch, x32Bit, rules)
	if err != nil {
		return -1, fmt.Errorf("assembling filter: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return -1, fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	fd, err := seccompSetFilter(prog)
	if err != nil {
		return -1, fmt.Errorf("SECCOMP_SET_MODE_FILTER: %w", err)
	}
	return fd, nil
}
