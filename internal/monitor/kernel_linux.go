// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package monitor

import "golang.org/x/sys/unix"

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
