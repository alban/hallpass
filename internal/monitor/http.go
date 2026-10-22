// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/alban/hallpass/internal/rules"
)

// Proxy serves the connections the monitor swaps in for the workload's
// own to a proxied host (internal/egress.Proxy).
type Proxy interface {
	// Serve serves conn, a connection the workload opened to dst, whose
	// names are names (the TLS server name must be one of them), made by
	// subject (a rules.Subject). It returns when the connection ends.
	Serve(conn net.Conn, dst netip.AddrPort, names []string, subject any)
	// Covers reports whether the proxy can terminate TLS for name.
	Covers(name string) bool
	// Injects reports whether the proxy has a credential for name.
	Injects(name string) bool
	// HasCredentials reports whether the proxy has a credential for any
	// host.
	HasCredentials() bool
}

// SetProxy makes the monitor send connections to port 443 of the
// addresses of proxied hosts (those with http rules, and that p covers)
// to p, instead of continuing them. Set before attaching.
func (m *Monitor) SetProxy(p Proxy) {
	m.mu.Lock()
	m.proxy = p
	m.mu.Unlock()
}

// proxiedNames returns the names of inet object o that make a connection
// to it go through the proxy: port 443 over TCP, a host the proxy covers
// with an http rule in rs (byRules), or a credential. None: a direct
// connection.
func (m *Monitor) proxiedNames(rs []rules.Rule, o *rules.InetObject) (names []string, byRules bool) {
	m.mu.Lock()
	p := m.proxy
	m.mu.Unlock()
	if p == nil || o == nil || o.Addr.Port() != 443 || (o.Proto != 6 && o.Proto != 17) || len(o.Names) == 0 {
		return nil, false
	}
	for _, n := range o.Names {
		if rules.ProxiedBy(rs, []string{n}) && p.Covers(n) {
			return o.Names, true
		}
	}
	for _, n := range o.Names {
		if p.Injects(n) && p.Covers(n) {
			return o.Names, false
		}
	}
	return nil, false
}

// DecideHTTP decides request obj (rules.OpHTTP) of the proxy, made by
// subject (what SetProxy's Serve was given): by the rules, or else by
// asking, like any other access, until ctx ends. why says what decided,
// for the proxy's error page.
func (m *Monitor) DecideHTTP(ctx context.Context, subject any, obj rules.HTTPObject) (allow bool, why string) {
	s, _ := subject.(rules.Subject)
	o := rules.Object{HTTP: &obj}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, "the session ended"
	}
	if !rules.ProxiedBy(m.rules, []string{obj.Host}) {
		// Proxied for a credential only: the connect was decided as
		// any other, its requests are not.
		m.mu.Unlock()
		return true, "no http rule for the host"
	}
	if v, id, ok := rules.Eval(m.rules, rules.OpHTTP, o, m.now()); ok && v != rules.Ask {
		m.mu.Unlock()
		m.reportHTTP(s, obj, v == rules.Allow, Reason{Rule: id})
		return v == rules.Allow, fmt.Sprintf("rule %d", id)
	}
	tgid := 0
	if len(s.Chain) > 0 {
		tgid = s.Chain[0].PID
	}
	key := fmt.Sprintf("%d\x00http\x00%s\x00%s", tgid, obj.Method, obj.URL())
	alive := waiter{alive: func() bool { return ctx.Err() == nil }}
	r := m.byKey[key]
	if r != nil {
		r.waiters = append(r.waiters, alive)
	} else {
		r = &request{
			pub:     &Request{Syscall: "http", Op: rules.OpHTTP, Objects: []rules.Object{o}, Subject: s},
			key:     key,
			op:      rules.OpHTTP,
			obj:     o,
			waiters: []waiter{alive},
			done:    make(chan struct{}),
		}
		m.addLocked(r)
	}
	m.mu.Unlock()
	select {
	case <-r.done:
	case <-ctx.Done():
		// The request is closed by poll once no waiter is alive.
		return false, "the connection closed"
	}
	if r.why.Died {
		return false, "nobody waits for the answer"
	}
	why = "answered"
	if r.why.Rule != 0 {
		why = fmt.Sprintf("rule %d", r.why.Rule)
	}
	return r.allow, why
}

// reportHTTP reports a request the rules decided (EventOptions.Decided).
func (m *Monitor) reportHTTP(s rules.Subject, obj rules.HTTPObject, allowed bool, why Reason) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decided == 0 {
		return
	}
	m.emitLocked(Event{Decided: &Decided{
		Time: m.now(), Syscall: "http", Op: rules.OpHTTP, Objects: []rules.Object{{HTTP: &obj}},
		Subject: s, Allowed: allowed, Why: []Reason{why}, Source: SourceProxy,
	}})
}
