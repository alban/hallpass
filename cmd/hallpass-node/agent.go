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
	"sync"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"

	"github.com/alban/hallpass/internal/sessionapi"
)

// maxState bounds the container process state runc sends.
const maxState = 1 << 20

// agent is the seccomp agent: runc hands it the listener of each mediated
// container (and of each process exec'd into one), and it runs one
// monitor per container.
type agent struct {
	cluster cluster
	hub     *sessionapi.Hub
	log     *slog.Logger

	mu       sync.Mutex
	sessions map[string]*session // by container id
}

func newAgent(c cluster, hub *sessionapi.Hub, log *slog.Logger) *agent {
	return &agent{cluster: c, hub: hub, log: log, sessions: map[string]*session{}}
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
	defer a.mu.Unlock()
	s := a.sessions[id]
	if s != nil {
		if err := s.m.Attach(fd, st.Pid); err == nil {
			a.log.Info("attached process", "container", id, "pid", st.Pid)
			return nil
		}
		// The session is ending: its last process exited.
	}
	var md metadata
	if err := json.Unmarshal([]byte(st.Metadata), &md); err != nil {
		return fmt.Errorf("listener metadata: %w", err)
	}
	pol, err := a.cluster.Policy(md.Policy)
	if err != nil {
		// Fail closed: deny what the implicit rules do not allow.
		a.log.Error("no policy, denying", "container", id, "err", err)
		pol = &Policy{Name: md.Policy}
	}
	s, err = newSession(id, st.Pid, md, pol, a.log)
	if err != nil {
		return err
	}
	if err := s.m.Attach(fd, st.Pid); err != nil {
		s.m.Close()
		return err
	}
	a.sessions[id] = s
	a.hub.Add(id, s.m, s)
	a.log.Info("session started", "container", id, "namespace", md.Namespace, "pod", md.Pod, "name", md.Container, "policy", pol.Name, "pid", st.Pid)
	go func() {
		s.run()
		a.mu.Lock()
		if a.sessions[id] == s {
			delete(a.sessions, id)
			a.hub.Remove(id)
		}
		a.mu.Unlock()
		s.m.Close()
		a.log.Info("session ended", "container", id)
	}()
	return nil
}
