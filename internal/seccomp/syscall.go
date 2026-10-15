// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"runtime"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var threadLocked bool

// LockThread pins the goroutine to its OS thread and records that the thread is
// ready for Install. The same thread must call execve afterwards.
func LockThread() {
	runtime.LockOSThread()
	threadLocked = true
}

type sockFprog struct {
	length uint16
	filter *bpf.RawInstruction
}

// seccompSetFilter loads prog with a listener. Once the supervisor has
// received a notification, only a fatal signal interrupts the wait for its
// answer (Linux 5.19+, skipped on older kernels): otherwise a signal would
// abort the syscall, which is then restarted, notified and asked about again.
func seccompSetFilter(prog []bpf.RawInstruction) (int, error) {
	fd, err := setFilter(prog, filterFlagNewLister|filterFlagWaitKillableRecv)
	if err == unix.EINVAL {
		fd, err = setFilter(prog, filterFlagNewLister)
	}
	return fd, err
}

func setFilter(prog []bpf.RawInstruction, flags uintptr) (int, error) {
	fprog := sockFprog{
		length: uint16(len(prog)),
		filter: &prog[0],
	}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		secompSetModeFilter,
		flags,
		uintptr(unsafe.Pointer(&fprog)),
	)
	runtime.KeepAlive(prog)
	runtime.KeepAlive(&fprog)
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

func ioctlPtr(fd int, req uint, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}
