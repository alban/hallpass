// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_X86_64

// x32 syscalls also report AUDIT_ARCH_X86_64 but have this bit set in the
// syscall number; they are refused so the legacy table cannot be bypassed.
const x32Bit = 0x40000000

// Rules returns the syscall rules for amd64, which also has the legacy
// non-*at path syscalls.
func Rules(allowUserns bool) []Rule {
	return append(commonRules(allowUserns),
		Rule{Nr: unix.SYS_OPEN, Name: "open", Kind: NotifyIfWrite, FlagsArg: 1, Op: "write", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_CREAT, Name: "creat", Kind: Notify, Op: "write", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_UNLINK, Name: "unlink", Kind: Notify, Op: "delete", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_RMDIR, Name: "rmdir", Kind: Notify, Op: "delete", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_MKDIR, Name: "mkdir", Kind: Notify, Op: "create directory", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_MKNOD, Name: "mknod", Kind: Notify, Op: "create", Paths: []PathArg{{-1, 0}}},
		Rule{Nr: unix.SYS_SYMLINK, Name: "symlink", Kind: Notify, Op: "create symlink", Paths: []PathArg{{-1, 1}}},
		Rule{Nr: unix.SYS_LINK, Name: "link", Kind: Notify, Op: "link", Paths: []PathArg{{-1, 0}, {-1, 1}}},
		Rule{Nr: unix.SYS_RENAME, Name: "rename", Kind: Notify, Op: "rename", Paths: []PathArg{{-1, 0}, {-1, 1}}},
	)
}
