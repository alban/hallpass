// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// runFilter executes the filter on a synthetic seccomp_data.
func runFilter(t *testing.T, prog []bpf.RawInstruction, arch uint32, nr int, args ...uint64) uint32 {
	t.Helper()
	ins, ok := bpf.Disassemble(prog)
	if !ok {
		t.Fatal("disassemble failed")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	// x/net/bpf loads in network byte order, the kernel's seccomp in host
	// order: store each 32-bit word big-endian so the VM sees the values
	// the kernel would. Only the low half of each argument is used.
	data := make([]byte, 64)
	binary.BigEndian.PutUint32(data[offNr:], uint32(nr))
	binary.BigEndian.PutUint32(data[offArch:], arch)
	for i, a := range args {
		binary.BigEndian.PutUint32(data[offArgs+8*i:], uint32(a))
	}
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(ret)
}

func TestFilter(t *testing.T) {
	prog, err := buildFilter(auditArch, x32Bit, Rules(false))
	if err != nil {
		t.Fatal(err)
	}
	const at = uint64(0xffffff9c) // AT_FDCWD
	for _, tc := range []struct {
		name string
		arch uint32
		nr   int
		args []uint64
		want uint32
	}{
		{"wrong arch", 0x1234, unix.SYS_OPENAT, nil, retKillProcess},
		{"openat read", auditArch, unix.SYS_OPENAT, []uint64{at, 0, unix.O_RDONLY | unix.O_CLOEXEC}, retAllow},
		{"openat write", auditArch, unix.SYS_OPENAT, []uint64{at, 0, unix.O_WRONLY}, retUserNotif},
		{"openat rdwr", auditArch, unix.SYS_OPENAT, []uint64{at, 0, unix.O_RDWR}, retUserNotif},
		{"openat creat", auditArch, unix.SYS_OPENAT, []uint64{at, 0, unix.O_RDONLY | unix.O_CREAT}, retUserNotif},
		{"openat trunc", auditArch, unix.SYS_OPENAT, []uint64{at, 0, unix.O_RDONLY | unix.O_TRUNC}, retUserNotif},
		{"unlinkat", auditArch, unix.SYS_UNLINKAT, nil, retUserNotif},
		{"renameat2", auditArch, unix.SYS_RENAMEAT2, nil, retUserNotif},
		{"openat2", auditArch, unix.SYS_OPENAT2, nil, retUserNotif},
		{"io_uring", auditArch, unix.SYS_IO_URING_SETUP, nil, retErrno | uint32(unix.EPERM)},
		{"unshare userns", auditArch, unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWUSER}, retErrno | uint32(unix.EPERM)},
		{"unshare mntns", auditArch, unix.SYS_UNSHARE, []uint64{unix.CLONE_NEWNS}, retErrno | uint32(unix.EPERM)},
		{"unshare files", auditArch, unix.SYS_UNSHARE, []uint64{unix.CLONE_FILES}, retAllow},
		{"clone thread", auditArch, unix.SYS_CLONE, []uint64{unix.CLONE_VM | unix.CLONE_THREAD}, retAllow},
		{"clone3", auditArch, unix.SYS_CLONE3, nil, retErrno | uint32(unix.ENOSYS)},
		{"read", auditArch, unix.SYS_READ, nil, retAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFilter(t, prog, tc.arch, tc.nr, tc.args...); got != tc.want {
				t.Errorf("got %#x, want %#x", got, tc.want)
			}
		})
	}
}

func TestFilterAllowUserns(t *testing.T) {
	prog, err := buildFilter(auditArch, x32Bit, Rules(true))
	if err != nil {
		t.Fatal(err)
	}
	if got := runFilter(t, prog, auditArch, unix.SYS_UNSHARE, unix.CLONE_NEWUSER); got != retAllow {
		t.Errorf("unshare(NEWUSER) = %#x, want allow", got)
	}
	if got := runFilter(t, prog, auditArch, unix.SYS_CLONE3); got != retAllow {
		t.Errorf("clone3 = %#x, want allow", got)
	}
}

func TestRulesHaveUniqueSyscalls(t *testing.T) {
	seen := map[int]string{}
	for _, r := range Rules(false) {
		if prev, ok := seen[r.Nr]; ok {
			t.Errorf("syscall %d in both %s and %s", r.Nr, prev, r.Name)
		}
		seen[r.Nr] = r.Name
	}
}
