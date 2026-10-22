// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import (
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// Notifier is a seccomp listener (*seccomp.Listener).
type Notifier interface {
	Recv(slot []byte) (seccomp.Notif, error)
	IDValid(id uint64) bool
	Continue(id uint64) error
	Deny(id uint64, errno int32) error
}

type listener struct {
	n       Notifier
	j       *seccomp.Journal
	wg      sync.WaitGroup // receivers and handlers
	root    int
	mountFD int             // strict: /proc/<root>/mountinfo, polled for changes
	hup     <-chan struct{} // closed when no task uses the filter
}

// Attach starts mediating the processes behind seccompFD. rootPID is the
// process the filter was installed on, in the monitor's pid namespace; in
// strict mode it becomes a BPF member. The launcher must keep it from
// running untrusted code until Attach returns. Called once per listener.
// The notifications in flight are in a journal on the heap: nothing
// recovers them.
func (m *Monitor) Attach(seccompFD, rootPID int) error {
	_, err := m.AttachJournal(seccompFD, rootPID, seccomp.NewJournal(seccomp.DefaultSlots))
	return err
}

// AttachJournal is Attach with the journal of the notifications in
// flight, whose size caps them. The notifications it already holds,
// received by a previous monitor (e.g. before a crash), are handled
// first. done is closed once no task uses the listener and the monitor
// no longer uses seccompFD or j: the caller may then close them.
func (m *Monitor) AttachJournal(seccompFD, rootPID int, j *seccomp.Journal) (done <-chan struct{}, err error) {
	l := seccomp.NewListener(seccompFD)
	hup := make(chan struct{})
	go func() {
		defer close(hup)
		// No events requested: poll still reports POLLHUP and POLLERR,
		// and does not wake up for pending notifications.
		fds := []unix.PollFd{{Fd: int32(seccompFD)}}
		for {
			_, err := unix.Poll(fds, -1)
			if err == unix.EINTR {
				continue
			}
			if err != nil || fds[0].Revents != 0 {
				return
			}
		}
	}()
	return m.attach(l, rootPID, hup, j)
}

// attach is Attach for any Notifier; hup is closed when no task uses it.
func (m *Monitor) attach(n Notifier, root int, hup <-chan struct{}, j *seccomp.Journal) (<-chan struct{}, error) {
	l := &listener{n: n, j: j, root: root, mountFD: -1, hup: hup}
	m.mu.Lock()
	if m.closed || m.finished {
		m.mu.Unlock()
		return nil, errors.New("monitor: closed")
	}
	m.mu.Unlock()
	if m.kernel != nil {
		// The root is not made a member here: it may still run the
		// container runtime's init (runc reopens its exec fifo). Each
		// task becomes one on its execve (exec).
		m.kmu.Lock()
		err := m.syncLocked(m.currentRules())
		if err == nil {
			l.mountFD, err = unix.Open(fmt.Sprintf("/proc/%d/mountinfo", root), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		}
		m.kmu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("strict mode: %w", err)
		}
	}
	m.mu.Lock()
	m.listeners = append(m.listeners, l)
	m.live++
	startKernel := m.kernel != nil && !m.kernelOn
	m.kernelOn = true
	m.mu.Unlock()
	if startKernel {
		go m.kernel.Events(m.kernelEvent)
	}
	m.replay(l)
	for i := 0; i < max(4, runtime.NumCPU()); i++ {
		l.wg.Add(1)
		go m.receiver(l)
	}
	done := make(chan struct{})
	go func() {
		<-hup
		m.mu.Lock()
		m.live--
		gone := m.live == 0
		m.mu.Unlock()
		go func() {
			// The journal outlives its slots in use.
			l.wg.Wait()
			close(done)
		}()
		if gone {
			m.finish()
		}
	}()
	return done, nil
}

// notifWaiter is the task of notification id of l.
func notifWaiter(l *listener, id uint64) waiter {
	return waiter{alive: func() bool { return l.n.IDValid(id) }}
}

// close closes what l holds open but its notifier.
func (l *listener) close() {
	if l.mountFD >= 0 {
		unix.Close(l.mountFD)
	}
}

// syscallTable is the table of the syscalls the monitor is notified of:
// every one, whatever the categories mediated.
func syscallTable() []seccomp.Rule { return seccomp.Rules(true) }
