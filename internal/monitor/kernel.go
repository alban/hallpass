// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"golang.org/x/sys/unix"
)

// toLSM translates r for the kernel. The BPF programs have no operations,
// no "ask" and see no unreadable paths: a file rule must cover every file
// op.
func toLSM(r rules.Rule) (*lsm.Rule, *lsm.ProcRule, error) {
	if r.Verdict == rules.Ask || r.Object.Unknown || r.Object.IsNet() || r.Ops&rules.OpFiles != rules.OpFiles {
		return nil, nil, fmt.Errorf("%w: %+v", ErrUnsupported, r)
	}
	deny := r.Verdict == rules.Deny
	if p := r.Object.Proc; p != nil {
		return nil, &lsm.ProcRule{Name: p.Name, Comm: p.Comm, Deny: deny, Expires: r.Expires}, nil
	}
	p := r.Object.Path
	return &lsm.Rule{Path: p.Path, Tree: p.Tree, Deny: deny, Expires: r.Expires}, nil, nil
}

// syncLocked makes the kernel's rules rs. kmu must be held.
func (m *Monitor) syncLocked(rs []rules.Rule) error {
	var paths []lsm.Rule
	var procs []lsm.ProcRule
	for _, r := range rs {
		p, pr, err := toLSM(r)
		if err != nil {
			return err
		}
		if p != nil {
			paths = append(paths, *p)
		}
		if pr != nil {
			procs = append(procs, *pr)
		}
	}
	return m.kernel.Sync(paths, procs)
}

// checkMounts resyncs the kernel's rules if the workload's mounts changed:
// they are keyed by mount. It runs before every syscall is continued, so
// the kernel never decides one with stale mounts the monitor knows about.
func (m *Monitor) checkMounts(l *listener) {
	if l.mountFD < 0 {
		return
	}
	m.kmu.Lock()
	defer m.kmu.Unlock()
	fds := []unix.PollFd{{Fd: int32(l.mountFD), Events: unix.POLLPRI}}
	n, err := unix.Poll(fds, 0)
	if err != nil || n == 0 || fds[0].Revents&(unix.POLLPRI|unix.POLLERR) == 0 {
		return
	}
	// The kernel reports a change once per poll: the event is consumed.
	if err := m.syncLocked(m.currentRules()); err != nil {
		m.warn("strict mode: resyncing the kernel's rules after a mount change: " + err.Error())
	}
}

// kernelEvent reports a decision of the BPF programs.
func (m *Monitor) kernelEvent(e lsm.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decided == 0 {
		return
	}
	m.emitLocked(Event{Decided: &Decided{
		Time:    m.now(),
		Syscall: e.Op,
		Op:      lsmOp(e.Op),
		Objects: []rules.Object{{Path: &rules.PathObject{Path: e.Path}}},
		Subject: rules.Subject{Chain: []rules.Task{{PID: int(e.PID), TID: int(e.PID), Comm: e.Comm}}},
		Allowed: e.Allowed,
		Why:     []Reason{{}},
		Source:  SourceLSM,
	}})
}

func lsmOp(name string) rules.Op {
	switch name {
	case "open":
		return rules.OpWrite
	case "create":
		return rules.OpCreate
	case "mkdir":
		return rules.OpMkdir
	case "rmdir", "unlink":
		return rules.OpDelete
	case "symlink":
		return rules.OpSymlink
	case "link":
		return rules.OpLink
	case "rename":
		return rules.OpRename
	case "truncate":
		return rules.OpTruncate
	}
	return rules.OpAll
}
