// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"fmt"
	"time"

	"github.com/alban/hallpass/internal/policy"
	"github.com/alban/hallpass/internal/ui"
)

// subject is something the user is asked about: a file path, or a kind of
// write to another process's /proc files.
type subject struct {
	key   string // coalesces concurrent identical requests
	req   ui.Request
	eval  func() policy.Decision
	grant func(ttl time.Duration) // covers req.Scope; 0: rest of the session
	never func()
	once  func() // strict mode: let the kernel allow it this time
	// unknown: the path could not be read (see unknownSubject).
	unknown bool
}

func (s *session) fileSubject(path string) subject {
	p := s.cfg.Policy
	folder := p.FolderFor(path)
	warn := p.Warn(path)
	if warn != "" {
		warn += " — secret store"
	}
	return subject{
		key:   path,
		req:   ui.Request{Path: path, Scope: folder, Never: "this path", Warn: warn},
		eval:  func() policy.Decision { return p.Eval(path) },
		grant: func(ttl time.Duration) { p.AllowFolderFor(folder, ttl) },
		never: func() { p.DenyPath(path) },
		once:  func() { s.allowOnce(path) },
	}
}

func (s *session) procSubject(path string, k policy.ProcKey) subject {
	p := s.cfg.Policy
	what := fmt.Sprintf("%s of %q processes outside the sandbox", k.Name, k.Comm)
	return subject{
		key:   "\x00proc\x00" + k.Name + "\x00" + k.Comm,
		req:   ui.Request{Path: path, Scope: what, Never: what},
		eval:  func() policy.Decision { return p.EvalProc(k) },
		grant: func(ttl time.Duration) { p.AllowProcFor(k, ttl) },
		never: func() { p.DenyProc(k) },
		once:  func() { s.allowProcOnce(k) },
	}
}

// unknownSubject asks about a syscall whose path hallpass could not read.
// Only lite mode gets here. Allowing it skips every rule, including the
// denies, and a process can make its path unreadable on purpose: so only
// "once" is offered, never a lasting grant, and the prompt is not shared
// with other syscalls.
func (s *session) unknownSubject(id uint64, err error) subject {
	return subject{
		key: fmt.Sprintf("\x00unknown\x00%d", id),
		req: ui.Request{
			Path:  "(unknown path)",
			Never: "all unknown paths",
			Warn:  "Unknown path — hallpass could not read it (" + err.Error() + ")",
		},
		eval: func() policy.Decision {
			if s.neverUnknown.Load() {
				return policy.Deny
			}
			return policy.Ask
		},
		grant:   func(time.Duration) {},
		never:   func() { s.neverUnknown.Store(true) },
		once:    func() {},
		unknown: true,
	}
}
