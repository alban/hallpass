// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"time"

	"github.com/alban/hallpass/internal/rules"
)

// request is a pending Request and the notifications waiting on it.
type request struct {
	pub     *Request
	key     string
	op      rules.Op
	obj     rules.Object
	advance bool // Request.Advance: only a verdict closes it
	waiters []waiter
	done    chan struct{}
	allow   bool
	// timedOut: denied by a verdict because nobody answered in time
	// (Decision.TimedOut).
	timedOut bool
	why      Reason
}

// waiter is a task waiting for a request's verdict.
type waiter struct {
	// alive reports whether the task still waits (on Linux, whether its
	// seccomp notification is still valid).
	alive func() bool
}

// addLocked makes r pending, with a new ID. mu must be held.
func (m *Monitor) addLocked(r *request) {
	m.nextReqID++
	r.pub.ID = m.nextReqID
	m.pending[r.pub.ID] = r
	m.byKey[r.key] = r
	m.emitLocked(Event{Opened: r.pub})
	if !m.polling {
		m.polling = true
		go m.poll()
	}
}

// closeLocked closes r. mu must be held.
func (m *Monitor) closeLocked(r *request, allow bool, why Reason) {
	delete(m.pending, r.pub.ID)
	delete(m.byKey, r.key)
	r.allow, r.why = allow, why
	close(r.done)
	m.emitLocked(Event{Closed: &Closed{ID: r.pub.ID, Why: why}})
}

// settleLocked closes the pending requests the rules now decide. mu must
// be held.
func (m *Monitor) settleLocked() {
	now := m.now()
	for _, r := range m.pending {
		if r.advance {
			continue
		}
		if v, id, ok := rules.Eval(m.rules, r.op, r.obj, now); ok && v != rules.Ask {
			m.closeLocked(r, v == rules.Allow, Reason{Rule: id})
		}
	}
}

// poll closes the requests whose tasks all died: the kernel does not signal
// a withdrawn notification. It runs only while requests are pending.
func (m *Monitor) poll() {
	t := time.NewTicker(pollPeriod)
	defer t.Stop()
	for range t.C {
		m.mu.Lock()
		if len(m.pending) == 0 {
			m.polling = false
			m.mu.Unlock()
			return
		}
		for _, r := range m.pending {
			alive := false
			for _, w := range r.waiters {
				if w.alive() {
					alive = true
					break
				}
			}
			if !alive {
				m.closeLocked(r, false, Reason{Died: true})
			}
		}
		m.mu.Unlock()
	}
}
