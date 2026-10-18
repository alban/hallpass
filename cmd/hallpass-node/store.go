// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/fdstore"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

// The fd-store keeps, for each session, an entry keyed by container id:
// fds [state, listener, journal, listener, journal, ...], where state is a
// sealed memfd holding a saved session. Strict mode's programs and maps
// are kept under lsmKey (see lsm.FDs), which no container id can be.
const lsmKey = "hallpass:lsm"

// saved is what recreates a session after the agent restarts.
type saved struct {
	Start    time.Time    `json:"start"`
	Pid      int          `json:"pid"`
	Metadata metadata     `json:"metadata"`
	Policy   Policy       `json:"policy"`
	Rules    []rules.Rule `json:"rules"`
	Pids     []int        `json:"pids"`             // of the listeners, in fd order
	Kernel   uint32       `json:"kernel,omitempty"` // the session id in the kernel, strict mode
}

// maxSaved bounds a saved session.
const maxSaved = 16 << 20

// storeRetry is how often the agent checks its fd-store connection.
var storeRetry = time.Second

// keepStore keeps the agent connected to the fd-store at path, until ctx
// is done: on each connection, it adopts the sessions it does not know,
// then stores all of its own.
func (a *agent) keepStore(ctx context.Context, path string) {
	// The first connection, by the caller, logs its own failure.
	a.pmu.Lock()
	logged := a.store == nil
	a.pmu.Unlock()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(storeRetry):
		}
		a.pmu.Lock()
		c := a.store
		if c != nil && !c.Alive() {
			a.log.Warn("fd-store connection lost")
			c.Close()
			a.store, c = nil, nil
		}
		a.pmu.Unlock()
		if c == nil {
			if err := a.connectStore(path); err != nil {
				if !logged {
					a.log.Warn("no fd-store: the requests in flight are lost if the agent restarts", "err", err)
					logged = true
				}
			} else {
				logged = false
			}
		}
	}
}

// connectStore connects to the fd-store, adopts its sessions, and stores
// the agent's.
func (a *agent) connectStore(path string) error {
	c, err := fdstore.Dial(path)
	if err != nil {
		return err
	}
	es, err := c.List()
	if err != nil {
		c.Close()
		return err
	}
	// The programs first: the strict sessions need them.
	for i, e := range es {
		if e.Key == lsmKey {
			a.adoptLSM(e)
			es = append(es[:i:i], es[i+1:]...)
			break
		}
	}
	for _, e := range es {
		a.adopt(c, e)
	}
	a.mu.Lock()
	l := a.lsm
	if a.lsmAdopted {
		a.lsmAdopted = false
		a.mu.Unlock()
		// The sessions of containers that ended while the agent was away.
		l.DropStale()
	} else {
		a.mu.Unlock()
	}
	a.pmu.Lock()
	a.store = c
	a.pmu.Unlock()
	a.log.Info("fd-store connected", "entries", len(es))
	a.persistLSM()
	a.mu.Lock()
	ss := make([]*session, 0, len(a.sessions))
	for _, s := range a.sessions {
		ss = append(ss, s)
	}
	a.mu.Unlock()
	for _, s := range ss {
		a.persist(s)
	}
	return nil
}

// adoptLSM takes over the programs of a previous agent, which still
// enforce strict mode on its containers, unless the agent has its own.
func (a *agent) adoptLSM(e fdstore.Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lsm != nil {
		fdstore.CloseAll(e.FDs)
		return
	}
	l, err := lsm.FromFDs(e.FDs)
	if err != nil {
		// Detached once the store drops them: the strict sessions are
		// dropped too (adopt).
		a.log.Error("strict mode: adopting the BPF programs", "err", err)
		return
	}
	a.lsm, a.lsmAdopted = l, true
	a.log.Info("strict mode: BPF programs adopted from the fd-store")
}

// persistLSM stores the programs in the fd-store, if any and connected.
func (a *agent) persistLSM() {
	a.mu.Lock()
	l := a.lsm
	a.mu.Unlock()
	if l == nil {
		return
	}
	a.pmu.Lock()
	defer a.pmu.Unlock()
	if a.store != nil {
		a.storeFailed(lsmKey, a.store.Put(lsmKey, l.FDs()))
	}
}

// adopt recreates the session of entry e, left by a previous agent, unless
// the agent already has it.
func (a *agent) adopt(c *fdstore.Client, e fdstore.Entry) {
	log := a.log.With("container", e.Key)
	a.mu.Lock()
	known := a.sessions[e.Key] != nil
	a.mu.Unlock()
	if known {
		fdstore.CloseAll(e.FDs)
		return
	}
	drop := func(msg string, err error) {
		log.Error(msg, "err", err)
		if err := c.Delete(e.Key); err != nil {
			log.Error("fd-store delete", "err", err)
		}
	}
	if len(e.FDs)%2 == 0 {
		fdstore.CloseAll(e.FDs)
		drop("fd-store entry", fmt.Errorf("%d fds", len(e.FDs)))
		return
	}
	var sv saved
	err := readSaved(e.FDs[0], &sv)
	unix.Close(e.FDs[0])
	if err == nil && len(sv.Pids) != len(e.FDs)/2 {
		err = fmt.Errorf("%d pids for %d listeners", len(sv.Pids), len(e.FDs)/2)
	}
	if err != nil {
		fdstore.CloseAll(e.FDs[1:])
		drop("saved session", err)
		return
	}
	now := time.Now()
	rs := []rules.Rule{}
	for _, r := range sv.Rules {
		if !r.Expired(now) {
			rs = append(rs, r)
		}
	}
	pol := sv.Policy
	var ks *lsm.Session
	if sv.Kernel != 0 {
		a.mu.Lock()
		l := a.lsm
		a.mu.Unlock()
		if l == nil {
			err = errors.New("strict session, and the BPF programs are lost")
		} else {
			ks, err = l.ResumeSession(sv.Kernel, sv.Pid)
		}
		if err != nil {
			fdstore.CloseAll(e.FDs[1:])
			drop("restore session", err)
			return
		}
	}
	s, err := newSession(e.Key, sv.Pid, sv.Metadata, &pol, rs, ks, a.log, a.rec)
	if err != nil {
		fdstore.CloseAll(e.FDs[1:])
		drop("restore session", err)
		return
	}
	s.start = sv.Start
	a.mu.Lock()
	for i, pid := range sv.Pids {
		lfd, jfd := e.FDs[1+2*i], e.FDs[2+2*i]
		j, err := seccomp.OpenJournal(jfd)
		if err != nil {
			// Its notifications in flight are lost: their tasks wait
			// until killed.
			log.Error("journal lost", "pid", pid, "err", err)
			unix.Close(jfd)
		}
		if err := a.attachLocked(s, lfd, pid, j); err != nil {
			log.Error("restore listener", "pid", pid, "err", err)
			unix.Close(lfd)
		}
	}
	if len(s.listeners) == 0 {
		a.mu.Unlock()
		s.close()
		drop("restore session", errors.New("no listener left"))
		return
	}
	a.startLocked(s)
	a.mu.Unlock()
	log.Info("session restored", "namespace", sv.Metadata.Namespace, "pod", sv.Metadata.Pod, "name", sv.Metadata.Container, "policy", pol.Name, "strict", ks != nil, "listeners", len(s.listeners))
}

// persist stores s in the fd-store, if connected.
func (a *agent) persist(s *session) {
	a.pmu.Lock()
	defer a.pmu.Unlock()
	if a.store == nil {
		return
	}
	a.mu.Lock()
	mine := a.sessions[s.id] == s
	ls := append([]*attached(nil), s.listeners...)
	a.mu.Unlock()
	if !mine || len(ls) == 0 {
		return
	}
	_, rs, _ := s.m.Snapshot()
	sv := saved{Start: s.start, Pid: s.pid, Metadata: s.md, Policy: *s.policy, Rules: rs}
	if s.ks != nil {
		sv.Kernel = s.ks.ID()
	}
	for _, l := range ls {
		sv.Pids = append(sv.Pids, l.pid)
	}
	fd, err := writeSaved(&sv)
	if err != nil {
		a.log.Error("fd-store", "container", s.id, "err", err)
		return
	}
	defer unix.Close(fd)
	fds := []int{fd}
	for _, l := range ls {
		fds = append(fds, l.fd, l.j.FD())
	}
	a.storeFailed(s.id, a.store.Put(s.id, fds))
}

// forget removes session id from the fd-store. pmu is held.
func (a *agent) forget(id string) {
	if a.store != nil {
		a.storeFailed(id, a.store.Delete(id))
	}
}

// storeFailed handles the error of an fd-store request. pmu is held.
func (a *agent) storeFailed(id string, err error) {
	if err == nil {
		return
	}
	a.log.Error("fd-store", "container", id, "err", err)
	var re *fdstore.RequestError
	if !errors.As(err, &re) {
		// keepStore reconnects, then stores every session again.
		a.store.Close()
		a.store = nil
	}
}

// writeSaved returns a sealed memfd holding sv.
func writeSaved(sv *saved) (int, error) {
	b, err := json.Marshal(sv)
	if err != nil {
		return -1, err
	}
	fd, err := unix.MemfdCreate("hallpass-session", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, err
	}
	for off := 0; off < len(b); {
		n, err := unix.Pwrite(fd, b[off:], int64(off))
		if err != nil {
			unix.Close(fd)
			return -1, err
		}
		off += n
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_SHRINK|unix.F_SEAL_GROW|unix.F_SEAL_SEAL); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// readSaved reads the saved session in memfd fd.
func readSaved(fd int, sv *saved) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Size > maxSaved {
		return fmt.Errorf("saved session of %d bytes", st.Size)
	}
	b := make([]byte, st.Size)
	for off := 0; off < len(b); {
		n, err := unix.Pread(fd, b[off:], int64(off))
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("saved session truncated")
		}
		off += n
	}
	return json.Unmarshal(b, sv)
}

// runFDStore is the fd-store command: it keeps the node agent's listeners
// while the agent restarts.
func runFDStore(args []string) error {
	fs := flag.NewFlagSet("fd-store", flag.ExitOnError)
	socket := fs.String("socket", defaultFDStore, "the fd-store socket (its directory is made root-only)")
	verbose := fs.Bool("v", false, "debug logs")
	_ = fs.Parse(args)
	if fs.NArg() != 0 {
		return fmt.Errorf("fd-store: unexpected arguments %v", fs.Args())
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ln, err := fdstore.Listen(*socket)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	s := &fdstore.Server{UID: 0, Log: log}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	log.Info("fd-store started", "socket", *socket)
	if err := s.Serve(ln); ctx.Err() == nil {
		return err
	}
	// The agent still holds the listeners, unless it is down too: their
	// waiting tasks then get ENOSYS.
	log.Info("fd-store stopped", "entries", s.Len())
	return nil
}
