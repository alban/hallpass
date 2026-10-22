// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package seccomp

import "golang.org/x/sys/unix"

// WriteIntentMask are the open flags that make an open a write: the monitor
// is notified of the opens that set any of them.
const WriteIntentMask = unix.O_ACCMODE | unix.O_CREAT | unix.O_TRUNC

const namespaceMask = unix.CLONE_NEWUSER | unix.CLONE_NEWNS

// commonRules are the rules shared by every supported architecture, using the
// *at syscalls that exist everywhere.
func commonRules(allowUserns bool) []Rule {
	rules := []Rule{
		{Nr: unix.SYS_OPENAT, Name: "openat", Kind: NotifyIfWrite, FlagsArg: 2, Op: "write", Paths: []PathArg{{0, 1}}},
		{Nr: unix.SYS_UNLINKAT, Name: "unlinkat", Kind: Notify, Op: "delete", Paths: []PathArg{{0, 1}}},
		{Nr: unix.SYS_MKDIRAT, Name: "mkdirat", Kind: Notify, Op: "create directory", Paths: []PathArg{{0, 1}}},
		{Nr: unix.SYS_MKNODAT, Name: "mknodat", Kind: Notify, Op: "create", Paths: []PathArg{{0, 1}}},
		{Nr: unix.SYS_SYMLINKAT, Name: "symlinkat", Kind: Notify, Op: "create symlink", Paths: []PathArg{{1, 2}}},
		// A hard link or rename touches both the source and the destination
		// directory: linking a protected file elsewhere would allow writing it.
		{Nr: unix.SYS_LINKAT, Name: "linkat", Kind: Notify, Op: "link", Paths: []PathArg{{0, 1}, {2, 3}}},
		{Nr: unix.SYS_RENAMEAT, Name: "renameat", Kind: Notify, Op: "rename", Paths: []PathArg{{0, 1}, {2, 3}}},
		{Nr: unix.SYS_RENAMEAT2, Name: "renameat2", Kind: Notify, Op: "rename", Paths: []PathArg{{0, 1}, {2, 3}}},
		{Nr: unix.SYS_TRUNCATE, Name: "truncate", Kind: Notify, Op: "truncate", Paths: []PathArg{{-1, 0}}},
		// Notified whatever the categories: in strict mode, the monitor
		// makes the thread a member first; this also lets a launcher
		// that does not wait for the monitor (runc) hold the first exec
		// until the monitor is attached. With exec mediated, the
		// program is checked too.
		{Nr: unix.SYS_EXECVE, Name: "execve", Kind: Notify, Op: "exec", Paths: []PathArg{{-1, 0}}},
		{Nr: unix.SYS_EXECVEAT, Name: "execveat", Kind: Notify, Op: "exec", Paths: []PathArg{{0, 1}}},

		// openat2 hides its flags in struct open_how, which cBPF cannot
		// read: every openat2 is notified, and the monitor continues
		// the ones without write intent. There is no fallback to
		// openat to rely on: libc has no openat2 wrapper, and callers
		// such as GNU tar fail on ENOSYS.
		{Nr: unix.SYS_OPENAT2, Name: "openat2", Kind: Notify, Op: "write", Paths: []PathArg{{0, 1}}},
		// io_uring performs I/O without per-operation syscalls.
		{Nr: unix.SYS_IO_URING_SETUP, Name: "io_uring_setup", Kind: Errno, Errno: uint32(unix.EPERM)},

		// Network: the destination of connect, and of the sends that
		// carry one. sendmsg and sendmmsg hide it in struct msghdr:
		// every call is notified, and the monitor continues the ones
		// without an address at once.
		{Nr: unix.SYS_CONNECT, Name: "connect", Kind: Notify, Op: "connect", Cat: Connect},
		{Nr: unix.SYS_SENDTO, Name: "sendto", Kind: NotifyIfSet, FlagsArg: 4, Op: "send", Cat: Connect},
		{Nr: unix.SYS_SENDMSG, Name: "sendmsg", Kind: Notify, Op: "send", Cat: Connect},
		{Nr: unix.SYS_SENDMMSG, Name: "sendmmsg", Kind: Notify, Op: "send", Cat: Connect},
	}
	if !allowUserns {
		// Inside a private mount namespace a process could bind-mount a
		// protected directory at a harmless-looking path; lite mode only
		// sees path strings, so new user/mount namespaces are refused.
		rules = append(rules,
			Rule{Nr: unix.SYS_UNSHARE, Name: "unshare", Kind: ErrnoIfNamespace, FlagsArg: 0, Errno: uint32(unix.EPERM)},
			Rule{Nr: unix.SYS_CLONE, Name: "clone", Kind: ErrnoIfNamespace, FlagsArg: 0, Errno: uint32(unix.EPERM)},
			// clone3 hides its flags in a struct; ENOSYS makes libc fall
			// back to clone.
			Rule{Nr: unix.SYS_CLONE3, Name: "clone3", Kind: Errno, Errno: uint32(unix.ENOSYS)},
			Rule{Nr: unix.SYS_SETNS, Name: "setns", Kind: Errno, Errno: uint32(unix.EPERM)},
		)
	}
	return rules
}

// Mask returns the flag bits tested in FlagsArg by NotifyIfWrite and
// ErrnoIfNamespace rules: the rule applies when any of them is set. It is 0
// for the other kinds.
func (r Rule) Mask() uint32 {
	switch r.Kind {
	case NotifyIfWrite:
		return WriteIntentMask
	case ErrnoIfNamespace:
		return namespaceMask
	}
	return 0
}
