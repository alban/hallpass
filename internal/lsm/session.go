// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Session is one sandbox: its members are checked against its rules only.
// Its paths are those seen by a process, its root, which can be in another
// mount namespace and chroot (a container).
type Session struct {
	l  *LSM
	id uint32
	// mountinfo is the root's; inRoot resolves paths in its root
	// directory, "" for this process's.
	mountinfo string
	inRoot    string

	mu    sync.Mutex
	cfg   hallpassSessionCfg
	nodes map[nodeKey]hallpassRuleVal
	procs map[hallpassProcKey]hallpassProcVal
	inet  map[hallpassInetKey]hallpassInetVal
	abs   map[hallpassAbstractKey]hallpassAbstractVal
	// The last rules given to Sync, for re-syncing in GrantOnce.
	lastRules []Rule
	lastProcs []ProcRule
	// once are the grants (see GrantOnce) that may still be in use.
	once   []*grant
	seq    uint64
	fn     func(Event)
	done   chan struct{}
	closed bool
}

// NewSession starts a session with no rules: its members may write nothing.
// Its paths are those seen by process root, or by this process if root is
// 0.
func (l *LSM) NewSession(root int) (*Session, error) {
	return l.newSession(0, root)
}

// ResumeSession is NewSession with the given id: that of a session of a
// previous owner of the programs (see FromFDs), whose members are still
// marked with it. Its rules stay in force until the first Sync.
func (l *LSM) ResumeSession(id uint32, root int) (*Session, error) {
	if id == 0 {
		return nil, errors.New("session id 0")
	}
	return l.newSession(id, root)
}

// newSession starts session id, or a new one if id is 0.
func (l *LSM) newSession(id uint32, root int) (*Session, error) {
	s := &Session{
		l:         l,
		mountinfo: "/proc/self/mountinfo",
		nodes:     map[nodeKey]hallpassRuleVal{},
		procs:     map[hallpassProcKey]hallpassProcVal{},
		inet:      map[hallpassInetKey]hallpassInetVal{},
		abs:       map[hallpassAbstractKey]hallpassAbstractVal{},
		done:      make(chan struct{}),
	}
	if root != 0 {
		s.mountinfo = fmt.Sprintf("/proc/%d/mountinfo", root)
		s.inRoot = fmt.Sprintf("/proc/%d/root", root)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if id == 0 {
		id = l.nextID
	}
	if l.sessions[id] != nil {
		return nil, fmt.Errorf("session %d exists", id)
	}
	s.id = id
	takeStale(l.stale, id, &s.nodes)
	takeStale(l.staleProcs, id, &s.procs)
	if c, ok := l.staleCfg[id]; ok {
		s.cfg = c
		delete(l.staleCfg, id)
	}
	takeStale(l.staleInet, id, &s.inet)
	takeStale(l.staleAbs, id, &s.abs)
	l.sessions[id] = s
	l.nextID = max(l.nextID, id+1)
	return s, nil
}

// takeStale moves the stale entries of session id, if any, to *into.
func takeStale[K comparable, V any](stale map[uint32]map[K]V, id uint32, into *map[K]V) {
	if m := stale[id]; m != nil {
		*into = m
		delete(stale, id)
	}
}

// ID is the session's id in the kernel.
func (s *Session) ID() uint32 { return s.id }

// Bits of session_cfg.mediate, those of seccomp.Category.
const (
	mediateFiles   = 1
	mediateExec    = 2
	mediateNetwork = 4
)

// Mediate sets what the programs check for the session's members: files,
// the programs they execute, network. Until it is called, a session
// mediates files only.
func (s *Session) Mediate(files, exec, network bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	s.cfg.Mediate = 0
	if files {
		s.cfg.Mediate |= mediateFiles
	}
	if exec {
		s.cfg.Mediate |= mediateExec
	}
	if network {
		s.cfg.Mediate |= mediateNetwork
	}
	return s.l.cfgs.Update(s.id, s.cfg, ebpf.UpdateAny)
}

// Close deletes the session's rules: its remaining members, if any, may
// write nothing.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.lastRules, s.lastProcs = nil, nil
	errs := []error{
		syncMap(s.l.rules, s.nodes, nil, s.ruleKey),
		syncMap(s.l.proc, s.procs, nil, same),
		syncMap(s.l.inet, s.inet, nil, same),
		syncMap(s.l.abstract, s.abs, nil, same),
	}
	s.nodes, s.procs, s.inet, s.abs = nil, nil, nil, nil
	if err := s.l.cfgs.Delete(s.id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, err)
	}
	s.releaseLocked()
	return errors.Join(errs...)
}

// release forgets s without touching the maps (LSM.Close).
func (s *Session) release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseLocked()
}

func (s *Session) releaseLocked() {
	if s.closed {
		return
	}
	s.closed = true
	for _, g := range s.once {
		unix.Close(g.pidfd)
	}
	s.once = nil
	s.l.mu.Lock()
	if s.l.sessions[s.id] == s {
		delete(s.l.sessions, s.id)
	}
	s.l.mu.Unlock()
	close(s.done)
}

// AddMember puts thread tid, or process tid's main thread, in the session;
// the tasks it creates from then on are members too. Its other threads are
// not, and an execve from one of them would leave the sandbox: mark the
// thread that calls execve.
func (s *Session) AddMember(tid int) error {
	fd, err := unix.PidfdOpen(tid, unix.PIDFD_THREAD)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", tid, err)
	}
	defer unix.Close(fd)
	return s.l.members.Update(uint32(fd), s.id, ebpf.UpdateAny)
}
