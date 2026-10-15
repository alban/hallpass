// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"fmt"
	"os"
	"time"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/seccomp"
)

// syncKernel pushes the policy's current rules to the kernel.
func (s *session) syncKernel() error {
	var rules []lsm.Rule
	var procs []lsm.ProcRule
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

// grantOnce lets the kernel allow the "allow once" answers in subs for
// syscall n only, which is about to be continued.
func (s *session) grantOnce(n seccomp.Notif, subs []subject) {
	var paths []string
	var proc lsm.ProcRule
	for _, sub := range subs {
		switch {
		case sub.proc != nil:
			proc = lsm.ProcRule{Name: sub.proc.Name, Comm: sub.proc.Comm}
		case sub.path != "":
			paths = append(paths, sub.path)
		}
	}
	if err := s.cfg.LSM.GrantOnce(int(n.PID), paths, proc); err != nil {
		fmt.Fprintf(os.Stderr, "hallpass: strict mode: allow once: %v\n", err)
	}
}

// restartTTL is how long an "allow once" answer covers the same syscall of
// the same thread again: a signal handler run during the syscall makes the
// kernel restart it, and seccomp notifies it again.
const restartTTL = 2 * time.Second

// restartKey identifies a syscall of a thread, with what it would write.
func restartKey(n seccomp.Notif, paths []string) string {
	return fmt.Sprintf("%d %d %x %q", n.PID, n.Nr, n.Args, paths)
}

// restarted reports whether the user allowed this syscall once very
// recently: it is the same one, restarted.
func (s *session) restarted(key string) bool {
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	now := time.Now()
	for k, t := range s.restart {
		if now.After(t) {
			delete(s.restart, k)
		}
	}
	_, ok := s.restart[key]
	return ok
}

func (s *session) allowedOnce(key string) {
	s.restartMu.Lock()
	s.restart[key] = time.Now().Add(restartTTL)
	s.restartMu.Unlock()
}
