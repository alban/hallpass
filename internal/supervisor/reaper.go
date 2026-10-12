// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// waiter is --wait=all's state: active once the command has exited and
// hallpass supervises its background processes; stop ends that early.
type waiter struct {
	active atomic.Bool
	once   sync.Once
	stop   chan struct{}
}

// Stop stops waiting for the background processes.
func (w *waiter) Stop() { w.once.Do(func() { close(w.stop) }) }

// waitAll returns once no process uses the seccomp filter any more (the
// notify fd reports POLLHUP), or the user stops waiting. Meanwhile the
// workers go on deciding, asking and logging.
func (s *session) waitAll() {
	hup := make(chan struct{})
	go func() {
		defer close(hup)
		// No events requested: poll still reports POLLHUP and POLLERR,
		// and does not wake up for pending notifications.
		fds := []unix.PollFd{{Fd: int32(s.listener.FD())}}
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
	// Most commands leave nothing behind: say nothing in that case.
	select {
	case <-hup:
		return
	case <-time.After(200 * time.Millisecond):
	}
	s.wait.active.Store(true)
	how := "SIGTERM"
	if s.cfg.TTY != nil {
		how = "Ctrl-] then s"
	}
	s.notice("hallpass: the command exited; still supervising its background processes (" + how + " to stop)")
	select {
	case <-hup:
	case <-s.wait.stop:
		s.notice("hallpass: stopped waiting; the remaining processes' writes now fail")
	}
}

// reap reaps every child: the command (main, whose status goes to mainDone)
// and the processes of the sandbox reparented to us as subreaper. It owns
// waiting for children: nothing else may wait for them (no cmd.Wait).
func reap(main int, sigchld <-chan os.Signal, mainDone chan<- unix.WaitStatus) {
	for {
		for {
			var ws unix.WaitStatus
			pid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
			if err == unix.EINTR {
				continue
			}
			if err != nil || pid <= 0 {
				break
			}
			if pid == main {
				mainDone <- ws
			}
		}
		<-sigchld
	}
}

// exitStatus is the shell's view of ws: the exit code, or 128+signal.
func exitStatus(ws unix.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}
