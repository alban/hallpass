// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import (
	"golang.org/x/net/bpf"
)

// seccomp return actions (uapi/linux/seccomp.h).
const (
	retKillProcess = 0x80000000
	retUserNotif   = 0x7fc00000
	retErrno       = 0x00050000
	retAllow       = 0x7fff0000
)

// seccomp_data field offsets. Arguments are 64-bit; on little-endian arm64 and
// amd64 the low 32 bits of args[i] are at offArgs + 8*i.
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

// buildFilter assembles the cBPF program for rules. The filter is
// intentionally simple: all policy lives in the supervisor (and in BPF-LSM in
// strict mode); the filter only decides which syscalls reach the supervisor.
func buildFilter(arch uint32, x32 uint32, rules []Rule) ([]bpf.RawInstruction, error) {
	ins := []bpf.Instruction{
		// A different syscall ABI would make the argument offsets wrong.
		bpf.LoadAbsolute{Off: offArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: arch, SkipTrue: 1},
		bpf.RetConstant{Val: retKillProcess},
	}
	if x32 != 0 {
		ins = append(ins,
			bpf.LoadAbsolute{Off: offNr, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: x32, SkipFalse: 1},
			bpf.RetConstant{Val: retKillProcess},
		)
	}

	for _, r := range rules {
		nr := uint32(r.Nr)
		switch r.Kind {
		case Notify, Errno:
			ret := uint32(retUserNotif)
			if r.Kind == Errno {
				ret = retErrno | (r.Errno & 0xffff)
			}
			ins = append(ins,
				bpf.LoadAbsolute{Off: offNr, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 1},
				bpf.RetConstant{Val: ret},
			)
		case NotifyIfWrite, ErrnoIfNamespace:
			mask := r.Mask()
			hit := uint32(retUserNotif)
			if r.Kind == ErrnoIfNamespace {
				hit = retErrno | (r.Errno & 0xffff)
			}
			ins = append(ins,
				bpf.LoadAbsolute{Off: offNr, Size: 4},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 5},
				bpf.LoadAbsolute{Off: uint32(offArgs + 8*r.FlagsArg), Size: 4},
				bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask},
				bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
				bpf.RetConstant{Val: hit},
				bpf.RetConstant{Val: retAllow},
			)
		}
	}

	ins = append(ins, bpf.RetConstant{Val: retAllow})
	return bpf.Assemble(ins)
}
