// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package ociseccomp turns the hallpass rule table (internal/seccomp) into an
// OCI seccomp profile, merged into the profile a container already has, so
// that a container runtime (runc) installs the filter and hands its listener
// to the hallpass node agent. The CLI and the agent then mediate the same
// syscalls.
//
// libseccomp, which runc uses to compile the profile, has two quirks that
// shape the merge:
//   - a syscall with an unconditional rule ignores conditional rules added
//     later, and an unconditional rule clears the conditional ones added
//     before it, so a hallpass rule replaces the base rules of its syscall
//     instead of being added next to them;
//   - runc compiles a rule with two conditions on the same argument as two
//     rules (OR instead of AND), so a hallpass condition on FlagsArg cannot be
//     combined with a base condition on the same argument.
//
// The merge only ever restricts the base profile: a syscall the base denies
// stays denied. Profiles the merge cannot express are refused rather than
// loosened.
package ociseccomp

import (
	"fmt"
	"math/bits"
	"runtime"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/alban/hallpass/internal/seccomp"
)

// FlagWaitKillableRecv is the OCI name of SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV.
const FlagWaitKillableRecv specs.LinuxSeccompFlag = "SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV"

// Options are the agent-specific fields of the profile.
type Options struct {
	// ListenerPath is the unix socket of the seccomp agent.
	ListenerPath string
	// ListenerMetadata is passed verbatim to the agent with the listener.
	ListenerMetadata string
	// WaitKillableRecv adds SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV. Only set
	// it when both the kernel and the runtime support it: runc before 1.5
	// refuses to create a container with a flag it does not know.
	WaitKillableRecv bool
}

// NativeArch is the only architecture kept in the profile: the monitor
// decodes syscall numbers and arguments with the native ABI, like the CLI's
// filter, which kills processes using another one. libseccomp applies the
// same bad-architecture action (kill) to the others.
var NativeArch = map[string]specs.Arch{
	"amd64": specs.ArchX86_64,
	"arm64": specs.ArchAARCH64,
}[runtime.GOARCH]

// Profile returns base (nil when the container is unconfined) with the
// hallpass rules merged in: hallpass rules first, then the base rules for the
// other syscalls. base is not modified.
func Profile(base *specs.LinuxSeccomp, rules []seccomp.Rule, opts Options) (*specs.LinuxSeccomp, error) {
	if NativeArch == "" {
		return nil, fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
	}
	if opts.ListenerPath == "" {
		return nil, fmt.Errorf("no listener path")
	}
	if base == nil {
		base = &specs.LinuxSeccomp{DefaultAction: specs.ActAllow}
	}
	if base.ListenerPath != "" {
		return nil, fmt.Errorf("the container's seccomp profile already has a listener (%s)", base.ListenerPath)
	}
	if base.DefaultAction == specs.ActNotify {
		return nil, fmt.Errorf("the container's seccomp profile notifies by default")
	}

	out := &specs.LinuxSeccomp{
		DefaultAction:    base.DefaultAction,
		DefaultErrnoRet:  base.DefaultErrnoRet,
		Architectures:    []specs.Arch{NativeArch},
		ListenerPath:     opts.ListenerPath,
		ListenerMetadata: opts.ListenerMetadata,
	}
	for _, f := range base.Flags {
		if f != FlagWaitKillableRecv {
			out.Flags = append(out.Flags, f)
		}
	}
	if opts.WaitKillableRecv {
		out.Flags = append(out.Flags, FlagWaitKillableRecv)
	}

	hallpass := map[string]bool{}
	for _, r := range rules {
		hallpass[r.Name] = true
	}
	// The base rules of each hallpass syscall, split out of multi-name rules.
	entries := map[string][]specs.LinuxSyscall{}
	var rest []specs.LinuxSyscall
	for _, s := range base.Syscalls {
		if s.Action == specs.ActNotify {
			return nil, fmt.Errorf("the container's seccomp profile already notifies %v", s.Names)
		}
		var others []string
		for _, name := range s.Names {
			if !hallpass[name] {
				others = append(others, name)
				continue
			}
			e := s
			e.Names = []string{name}
			entries[name] = append(entries[name], e)
		}
		if len(others) > 0 {
			e := s
			e.Names = others
			rest = append(rest, e)
		}
	}

	m := merger{defaultAction: base.DefaultAction}
	for _, r := range rules {
		var (
			syscalls []specs.LinuxSyscall
			err      error
		)
		switch r.Kind {
		case seccomp.Notify:
			syscalls, err = m.always(r, entries[r.Name], specs.ActNotify, nil)
		case seccomp.Errno:
			syscalls, err = m.always(r, entries[r.Name], specs.ActErrno, errnoRet(r.Errno))
		case seccomp.NotifyIfWrite:
			syscalls, err = m.ifFlags(r, entries[r.Name], specs.ActNotify, nil)
		case seccomp.ErrnoIfNamespace:
			syscalls, err = m.ifFlags(r, entries[r.Name], specs.ActErrno, errnoRet(r.Errno))
		default:
			err = fmt.Errorf("unknown rule kind %d", r.Kind)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", r.Name, err)
		}
		out.Syscalls = append(out.Syscalls, syscalls...)
	}
	out.Syscalls = append(out.Syscalls, rest...)
	return out, nil
}

type merger struct {
	defaultAction specs.LinuxSeccompAction
}

// allows reports whether action lets the syscall run.
func allows(action specs.LinuxSeccompAction) bool {
	return action == specs.ActAllow || action == specs.ActLog
}

func errnoRet(errno uint32) *uint {
	e := uint(errno)
	return &e
}

func alwaysDenied(entries []specs.LinuxSyscall) bool {
	for _, e := range entries {
		if len(e.Args) == 0 && !allows(e.Action) {
			return true
		}
	}
	return false
}

// always handles the rules that apply action whatever the arguments: what
// the base allows gets action, what it denies stays denied.
func (m merger) always(r seccomp.Rule, entries []specs.LinuxSyscall, action specs.LinuxSeccompAction, errno *uint) ([]specs.LinuxSyscall, error) {
	if alwaysDenied(entries) {
		return entries, nil
	}
	if allows(m.defaultAction) {
		for _, e := range entries {
			if !allows(e.Action) {
				// "action, except when the base denies" needs a
				// conditional and an unconditional rule on the same
				// syscall, which libseccomp cannot combine.
				return nil, fmt.Errorf("conditional %s rule in the container's seccomp profile", e.Action)
			}
		}
		return []specs.LinuxSyscall{{Names: []string{r.Name}, Action: action, ErrnoRet: errno}}, nil
	}
	var out []specs.LinuxSyscall
	for _, e := range entries {
		if allows(e.Action) {
			e.Action, e.ErrnoRet = action, errno
		}
		out = append(out, e)
	}
	return out, nil
}

// ifFlags handles the rules that apply action when any bit of r.Mask() is
// set in r.FlagsArg, and leave the syscall to the base otherwise. libseccomp
// has no "any bit set" operator, so each bit gets its own rule.
func (m merger) ifFlags(r seccomp.Rule, entries []specs.LinuxSyscall, action specs.LinuxSeccompAction, errno *uint) ([]specs.LinuxSyscall, error) {
	if alwaysDenied(entries) {
		return entries, nil
	}
	mask := uint64(r.Mask())
	idx := uint(r.FlagsArg)
	hits := func(args []specs.LinuxSeccompArg) []specs.LinuxSyscall {
		var out []specs.LinuxSyscall
		for b := mask; b != 0; b &= b - 1 {
			bit := uint64(1) << bits.TrailingZeros64(b)
			out = append(out, specs.LinuxSyscall{
				Names:    []string{r.Name},
				Action:   action,
				ErrnoRet: errno,
				Args:     append(clone(args), specs.LinuxSeccompArg{Index: idx, Value: bit, ValueTwo: bit, Op: specs.OpMaskedEqual}),
			})
		}
		return out
	}

	var out []specs.LinuxSyscall
	if allows(m.defaultAction) {
		// Whatever the base rules allow, the default allows too: the
		// flag rules alone are enough, next to the base's denials.
		out = hits(nil)
	}
	for _, e := range entries {
		if !allows(e.Action) {
			out = append(out, e)
			continue
		}
		if a, ok := argAt(e.Args, idx); ok {
			if excludes(a, mask) {
				// The base already restricts the flags to values
				// without these bits (e.g. clone in the
				// RuntimeDefault profile): what it allows is fine.
				out = append(out, e)
				continue
			}
			return nil, fmt.Errorf("the container's seccomp profile has a condition on argument %d", idx)
		}
		if !allows(m.defaultAction) {
			out = append(out, hits(e.Args)...)
		}
		if len(e.Args) == 0 && e.Action == m.defaultAction {
			continue
		}
		e.Args = append(clone(e.Args), specs.LinuxSeccompArg{Index: idx, Value: mask, ValueTwo: 0, Op: specs.OpMaskedEqual})
		out = append(out, e)
	}
	return out, nil
}

// argAt returns the condition on argument idx. Several conditions on one
// argument are ORed by runc: they are returned as an unknown condition.
func argAt(args []specs.LinuxSeccompArg, idx uint) (specs.LinuxSeccompArg, bool) {
	var found specs.LinuxSeccompArg
	n := 0
	for _, a := range args {
		if a.Index == idx {
			found = a
			n++
		}
	}
	if n > 1 {
		return specs.LinuxSeccompArg{Index: idx}, true
	}
	return found, n == 1
}

// excludes reports whether condition a only matches values with no bit of
// mask set.
func excludes(a specs.LinuxSeccompArg, mask uint64) bool {
	switch a.Op {
	case specs.OpMaskedEqual:
		return a.Value&mask == mask && a.ValueTwo&mask == 0
	case specs.OpEqualTo:
		return a.Value&mask == 0
	}
	return false
}

func clone(args []specs.LinuxSeccompArg) []specs.LinuxSeccompArg {
	return append([]specs.LinuxSeccompArg(nil), args...)
}
