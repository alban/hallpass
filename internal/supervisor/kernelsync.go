// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"fmt"
	"os"
	"time"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/policy"
)

// syncKernel pushes the policy's current rules and the pending "allow once"
// answers to the kernel.
func (s *session) syncKernel() error {
	now := time.Now()
	s.onceMu.Lock()
	once := s.once[:0]
	for _, r := range s.once {
		if r.Expires.After(now) {
			once = append(once, r)
		}
	}
	s.once = once
	onceProc := s.onceProc[:0]
	for _, r := range s.onceProc {
		if r.Expires.After(now) {
			onceProc = append(onceProc, r)
		}
	}
	s.onceProc = onceProc
	rules := append([]lsm.Rule(nil), once...)
	procs := append([]lsm.ProcRule(nil), onceProc...)
	s.onceMu.Unlock()

	for _, r := range s.cfg.Policy.Rules() {
		rules = append(rules, lsm.Rule{Path: r.Path, Tree: r.Tree, Deny: r.Deny, Expires: r.Expires})
	}
	for _, r := range s.cfg.Policy.ProcRules() {
		procs = append(procs, lsm.ProcRule{Name: r.Name, Comm: r.Comm, Deny: r.Deny, Expires: r.Expires})
	}
	return s.cfg.LSM.Sync(rules, procs)
}

func (s *session) syncOrWarn() {
	if err := s.syncKernel(); err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: strict mode: updating the kernel's rules: %v\n", err)
	}
}

func (s *session) periodicSync(done <-chan struct{}) {
	t := time.NewTicker(syncPeriod)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			s.syncOrWarn()
		}
	}
}

// kernelEvents logs the decisions of the BPF programs: denials (also of
// operations the seccomp filter does not see, e.g. through io_uring).
func (s *session) kernelEvents() {
	s.cfg.LSM.Events(func(e lsm.Event) {
		d := "deny"
		if e.Allowed {
			d = "allow"
		}
		s.log(logEntry{PID: e.PID, Exe: e.Comm, Syscall: e.Op, Path: e.Path, Decision: d, Reason: "lsm"})
	})
}

// allowOnce lets the kernel allow exactly path for a moment, for the
// syscall about to be continued.
func (s *session) allowOnce(path string) {
	s.onceMu.Lock()
	s.once = append(s.once, lsm.Rule{Path: path, Expires: time.Now().Add(onceTTL)})
	s.onceMu.Unlock()
}

func (s *session) allowProcOnce(k policy.ProcKey) {
	s.onceMu.Lock()
	s.onceProc = append(s.onceProc, lsm.ProcRule{Name: k.Name, Comm: k.Comm, Expires: time.Now().Add(onceTTL)})
	s.onceMu.Unlock()
}
