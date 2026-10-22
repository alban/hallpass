// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package lsm is strict mode's enforcement: BPF-LSM programs that check every
// write of the sandbox against the session's rules in the kernel, on the
// object being modified, so path races and bind mounts cannot get around the
// decisions taken by the seccomp supervisor.
//
// Files are named by their path inside their filesystem (see bpf/hallpass.bpf.c),
// so a rule on a host path also covers the same files reached through another
// bind mount or mount namespace.
//
// The package is split by concern: this file has the LSM and the kernel
// checks, load.go loading the programs and handing them over, session.go
// the sessions and their members, rules.go the file rules and one-time
// grants, net.go the network rules, events.go the decisions reported by the
// programs.
package lsm

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

const (
	rootCookie = 1 << 63
	forever    = math.MaxUint64
	nameLen    = 256
)

// kfuncs are the kernel functions bpf/hallpass.bpf.c calls. The programs do
// not load without them.
var kfuncs = []string{"bpf_path_d_path", "bpf_preempt_disable", "bpf_preempt_enable", "bpf_task_from_pid", "bpf_task_release"}

// Supported reports whether the programs can load on this kernel: its BTF
// must have every kfunc they call.
func Supported() error {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("cannot read the kernel BTF: %w", err)
	}
	var missing []string
	for _, name := range kfuncs {
		var fn *btf.Func
		if err := spec.TypeByName(name, &fn); err != nil {
			missing = append(missing, name)
		}
	}
	if missing != nil {
		return fmt.Errorf("the kernel lacks the kfuncs %s, needed by strict mode (Linux 6.12 has them)", strings.Join(missing, ", "))
	}
	return nil
}

// Active reports whether BPF-LSM programs load and run on this kernel: they
// must be supported, and bpf must be in the active LSM list, otherwise
// programs attach but are never called.
func Active() error {
	return ActiveIn("/")
}

// ActiveIn is Active, reading the active LSM list in root directory root:
// the host's, for a process in a container (/proc/1/root). Where securityfs
// is not mounted there (e.g. a kind node), it mounts its own, which needs
// CAP_SYS_ADMIN.
func ActiveIn(root string) error {
	if err := Supported(); err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(root, "/sys/kernel/security/lsm"))
	if errors.Is(err, os.ErrNotExist) {
		b, err = readOwnSecurityfs()
	}
	if err != nil {
		return fmt.Errorf("cannot read the active LSMs: %w", err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return nil
		}
	}
	return fmt.Errorf("BPF-LSM is not active (%s); add bpf to the lsm= kernel parameter", strings.TrimSpace(string(b)))
}

// readOwnSecurityfs reads the active LSM list from a new securityfs mount,
// detached: attached nowhere, gone once closed.
func readOwnSecurityfs() ([]byte, error) {
	fsfd, err := unix.Fsopen("securityfs", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fsopen securityfs: %w", err)
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return nil, fmt.Errorf("securityfs: %w", err)
	}
	mfd, err := unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, unix.MOUNT_ATTR_RDONLY|unix.MOUNT_ATTR_NOSUID|unix.MOUNT_ATTR_NODEV|unix.MOUNT_ATTR_NOEXEC)
	if err != nil {
		return nil, fmt.Errorf("fsmount securityfs: %w", err)
	}
	defer unix.Close(mfd)
	fd, err := unix.Openat(mfd, "lsm", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "securityfs/lsm")
	defer f.Close()
	return io.ReadAll(f)
}

type nodeKey struct {
	parent uint64
	name   string
}

// LSM is a loaded and attached set of programs. It enforces the rules of
// any number of sessions (see Session), each with its own members.
type LSM struct {
	members, protected, grants, rules, proc, events, cfgs *ebpf.Map
	inet, abstract                                        *ebpf.Map
	// links keep the programs attached; closing them detaches.
	links []io.Closer
	// linkFDs are the links' fds, for handing them to another process.
	linkFDs []int
	rd      *ringbuf.Reader

	mu sync.Mutex
	// cookies name the rule nodes. They are shared by all sessions, whose
	// rule keys also have the session id.
	cookies  map[nodeKey]uint64
	next     uint64
	sessions map[uint32]*Session
	nextID   uint32
	// stale are the rules and procs found in the maps by FromFDs, per
	// session, for ResumeSession; see DropStale.
	stale      map[uint32]map[nodeKey]hallpassRuleVal
	staleProcs map[uint32]map[hallpassProcKey]hallpassProcVal
	staleCfg   map[uint32]hallpassSessionCfg
	staleInet  map[uint32]map[hallpassInetKey]hallpassInetVal
	staleAbs   map[uint32]map[hallpassAbstractKey]hallpassAbstractVal
	reading    bool
}

func newLSM() *LSM {
	return &LSM{
		cookies:  map[nodeKey]uint64{},
		next:     1,
		sessions: map[uint32]*Session{},
		nextID:   1,
	}
}

// Protect forbids members of all sessions to signal process pid (all its
// threads).
func (l *LSM) Protect(pid int) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", pid, err)
	}
	defer unix.Close(fd)
	return l.protected.Update(uint32(fd), uint8(1), ebpf.UpdateAny)
}
