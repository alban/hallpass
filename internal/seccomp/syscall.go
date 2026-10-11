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

func seccompSetFilter(prog []bpf.RawInstruction) (int, error) {
	fprog := sockFprog{
		length: uint16(len(prog)),
		filter: &prog[0],
	}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP,
		secompSetModeFilter,
		filterFlagNewLister,
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
