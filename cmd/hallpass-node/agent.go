// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/fdstore"
	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/seccomp"
	"github.com/alban/hallpass/internal/sessionapi"
)

// maxState bounds the container process state runc sends.
const maxState = 1 << 20

// agent is the seccomp agent: runc hands it the listener of each mediated
// container (and of each process exec'd into one), and it runs one
// monitor per container.
type agent struct {
	cluster cluster
	node    *sessionapi.Node
	log     *slog.Logger
	rec     recorder
	// maxInflight is the journal size of a listener: the most
	// notifications in flight (most waiting for an answer).
	maxInflight int
	// lsm enforces strict mode: loaded, or adopted from a previous agent
	// (its strict sessions keep it). Set before the agent serves.
	lsm *lsm.LSM
	// strict: new sessions are in strict mode (lsm is set).
	strict bool
	// lsmAdopted: lsm came from the fd-store, and its stale sessions are
	// dropped once those of the store are adopted.
	lsmAdopted bool

	mu       sync.Mutex
	sessions map[string]*session // by container id

	// pmu orders the fd-store updates, and guards store. Taken before mu.
	pmu   sync.Mutex
	store *fdstore.Client // nil: not connected
}

func newAgent(c cluster, node *sessionapi.Node, log *slog.Logger, rec recorder, maxInflight int) *agent {
	return &agent{cluster: c, node: node, log: log, rec: rec, maxInflight: maxInflight, sessions: map[string]*session{}}
}

// setupStrict decides whether new sessions are in strict mode, for --mode
// auto, lite or strict, and loads the programs unless adopted from the
// fd-store. hostRoot holds the host's active LSM list. Called before the
// agent serves.
func (a *agent) setupStrict(mode, hostRoot string) error {
	var why error
	switch mode {
	case "lite":
		why = errors.New("--mode=lite")
	case "auto", "strict":
		why = lsm.ActiveIn(hostRoot)
	default:
		return fmt.Errorf("--mode %q: want auto, lite or strict", mode)
	}
	a.mu.Lock()
	l := a.lsm
	a.mu.Unlock()
	if why == nil && l == nil {
		var err error
		if l, err = lsm.Load(false); err != nil {
			why = fmt.Errorf("loading the BPF programs: %w", err)
		} else {
			a.mu.Lock()
			a.lsm = l
			a.mu.Unlock()
			a.persistLSM()
		}
	}
	if why != nil && mode == "strict" {
		return fmt.Errorf("--mode=strict: %w", why)
	}
	if l != nil {
		// Members of the strict sessions, adopted ones included, may not
		// signal the agent.
		if err := l.Protect(os.Getpid()); err != nil {
			return fmt.Errorf("strict mode: %w", err)
		}
	}
	a.mu.Lock()
	a.strict = why == nil
	a.mu.Unlock()
	if why != nil {
		a.log.Info("lite mode", "why", why)
	} else {
		a.log.Info("strict mode")
	}
	return nil
}

// listen creates the agent socket. Its directory is root-only: whoever can
// connect can hand the agent listeners, so there is no peer check.
func listen(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
}

// serve accepts runc's connections until ln is closed.
func (a *agent) serve(ln *net.UnixListener) error {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			if err := a.handle(c); err != nil {
				a.log.Error("seccomp agent", "err", err)
			}
		}()
	}
}

// handle receives one listener: the OCI container process state, with the
// listener fd attached (SCM_RIGHTS).
func (a *agent) handle(c *net.UnixConn) error {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	state, fd, err := recvState(c)
	if err != nil {
		return err
	}
	if err := a.attach(state, fd); err != nil {
		unix.Close(fd)
		return fmt.Errorf("container %s: %w", state.State.ID, err)
	}
	return nil
}

// recvState reads a specs.ContainerProcessState and its seccomp fd.
func recvState(c *net.UnixConn) (*specs.ContainerProcessState, int, error) {
	buf := make([]byte, 64<<10)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, -1, err
	}
	var fds []int
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, -1, err
	}
	for _, m := range msgs {
		if r, err := unix.ParseUnixRights(&m); err == nil {
			fds = append(fds, r...)
		}
	}
	fail := func(err error) (*specs.ContainerProcessState, int, error) {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, -1, err
	}
	rest, err := io.ReadAll(io.LimitReader(c, maxState))
	if err != nil {
		return fail(err)
	}
	data := append(buf[:n], rest...)
	var st specs.ContainerProcessState
	if err := json.Unmarshal(data, &st); err != nil {
		return fail(fmt.Errorf("container process state: %w", err))
	}
	if len(fds) != 1 || len(st.Fds) != 1 || st.Fds[0] != specs.SeccompFdName {
		return fail(fmt.Errorf("container %s: want one %s, got fds %v (%d received)", st.State.ID, specs.SeccompFdName, st.Fds, len(fds)))
	}
	return &st, fds[0], nil
}

// attach hands fd to the container's monitor, creating its session on
// the first listener.
func (a *agent) attach(st *specs.ContainerProcessState, fd int) error {
	id := st.State.ID
	if id == "" || st.Pid <= 0 {
		return fmt.Errorf("incomplete container process state")
	}
	a.mu.Lock()
	s := a.sessions[id]
	if s != nil {
		if err := a.attachLocked(s, fd, st.Pid, nil); err == nil {
			a.mu.Unlock()
			a.log.Info("attached process", "container", id, "pid", st.Pid)
			a.persist(s)
			return nil
		}
		// The session is ending: its last process exited.
	}
	var md metadata
	if err := json.Unmarshal([]byte(st.Metadata), &md); err != nil {
		a.mu.Unlock()
		return fmt.Errorf("listener metadata: %w", err)
	}
	pol, err := a.cluster.Policy(md.Policy)
	if err != nil {
		// Fail closed: deny what the implicit rules do not allow.
		a.log.Error("no policy, denying", "container", id, "err", err)
		pol = &Policy{Name: md.Policy}
	}
	var ks *lsm.Session
	if a.strict {
		if ks, err = a.lsm.NewSession(st.Pid); err != nil {
			a.mu.Unlock()
			return fmt.Errorf("strict mode: %w", err)
		}
	}
	s, err = newSession(id, st.Pid, md, pol, nil, ks, a.log, a.rec)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if err := a.attachLocked(s, fd, st.Pid, nil); err != nil {
		a.mu.Unlock()
		s.close()
		return err
	}
	a.startLocked(s)
	a.mu.Unlock()
	a.log.Info("session started", "container", id, "namespace", md.Namespace, "pod", md.Pod, "name", md.Container, "policy", pol.Name, "strict", ks != nil, "pid", st.Pid)
	a.persist(s)
	return nil
}

// attachLocked attaches listener fd of process pid to s, with journal j,
// or a new one if nil. On an error, fd stays the caller's, j is closed.
func (a *agent) attachLocked(s *session, fd, pid int, j *seccomp.Journal) error {
	if j == nil {
		var err error
		// Without a journal, a crash would lose the notifications in
		// flight: fail closed instead.
		if j, err = seccomp.NewMemfdJournal("hallpass-"+s.id, a.maxInflight); err != nil {
			return fmt.Errorf("journal: %w", err)
		}
	}
	done, err := s.m.AttachJournal(fd, pid, j)
	if err != nil {
		j.Close()
		return err
	}
	l := &attached{pid: pid, fd: fd, j: j}
	s.listeners = append(s.listeners, l)
	go func() {
		<-done
		a.pmu.Lock()
		a.mu.Lock()
		s.listeners = slices.DeleteFunc(s.listeners, func(x *attached) bool { return x == l })
		a.mu.Unlock()
		// Under pmu: persist does not send them once closed.
		unix.Close(l.fd)
		l.j.Close()
		a.pmu.Unlock()
		a.persist(s)
	}()
	return nil
}

// startLocked registers s, until its last process exits.
func (a *agent) startLocked(s *session) {
	id := s.id
	s.onRules = func() { a.persist(s) }
	a.sessions[id] = s
	a.node.Add(id, s.m, s)
	go func() {
		s.run()
		a.pmu.Lock()
		a.mu.Lock()
		mine := a.sessions[id] == s
		if mine {
			delete(a.sessions, id)
			a.node.Remove(id)
		}
		a.mu.Unlock()
		if mine {
			a.forget(id)
		}
		a.pmu.Unlock()
		s.close()
		a.log.Info("session ended", "container", id)
	}()
}
