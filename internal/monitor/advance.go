// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/procfs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
	"golang.org/x/sys/unix"
)

// AdvanceDir is where the workload asks for access in advance: an execve
// of AdvanceDir+"request?op=write&path=/dir/**&for=10m&reason=..." opens a
// Request with Advance set, and AdvanceDir+"check?..." asks whether it
// would be needed. The path never exists: without a monitor, the kernel
// fails the execve with ENOENT. The monitor never continues it, it answers
// with an errno:
//
//   - EEXIST: the rules already allow it (no request)
//   - EALREADY: a verdict allowed the request
//   - EPERM: a rule denies it, or a verdict denied the request
//   - ETIMEDOUT: denied because nobody answered in time
//     (Decision.TimedOut)
//   - EINVAL, ENAMETOOLONG: malformed or too long
//   - ENOMSG: (check only) a request would be needed
//
// See docs/devel/monitor.md.
const AdvanceDir = "/proc/self/hallpass/"

// advanceSlack bounds how much shorter than asked an existing grant may
// last and still cover an advance request (a tenth of it at most).
const advanceSlack = time.Minute

// Advance describes a Request the workload made in advance, before
// accessing Objects[0]. Op is the operations asked for.
type Advance struct {
	Tree   bool          // Objects[0] and everything below it
	For    time.Duration // how long the grant is asked for; 0: the rest of the session
	Reason string        // written by the workload: untrusted, display only
}

// advanceQuery is a parsed advance request.
type advanceQuery struct {
	check bool
	op    rules.Op
	path  string // absolute and clean, not resolved yet
	adv   Advance
}

// parseAdvance parses raw, an execve path starting with AdvanceDir.
func parseAdvance(raw string) (advanceQuery, unix.Errno) {
	var q advanceQuery
	verb, query, _ := strings.Cut(strings.TrimPrefix(raw, AdvanceDir), "?")
	switch verb {
	case "request":
	case "check":
		q.check = true
	default:
		return q, unix.EINVAL
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return q, unix.EINVAL
	}
	for k, v := range vals {
		if len(v) != 1 {
			return q, unix.EINVAL
		}
		switch k {
		case "op":
			// The only file op rules can grant: every file op (strict
			// mode's rules have no finer ones).
			if v[0] != "write" {
				return q, unix.EINVAL
			}
			q.op = rules.OpFiles
		case "path":
			p := v[0]
			if base, ok := strings.CutSuffix(p, "/**"); ok {
				q.adv.Tree = true
				p = base
				if p == "" {
					p = "/"
				}
			}
			if !filepath.IsAbs(p) || strings.ContainsAny(p, "*?[") {
				return q, unix.EINVAL
			}
			q.path = filepath.Clean(p)
		case "for":
			d, err := time.ParseDuration(v[0])
			if err != nil || d <= 0 {
				return q, unix.EINVAL
			}
			q.adv.For = d
		case "reason":
			q.adv.Reason = v[0]
		default:
			return q, unix.EINVAL
		}
	}
	if q.op == 0 || q.path == "" {
		return q, unix.EINVAL
	}
	return q, 0
}

// advance answers an advance request or check, raw, made by execve n, or
// returns ask, which waits for a verdict and must run in its own
// goroutine. rerr is the error reading raw. The execve is never continued.
func (m *Monitor) advance(l *listener, n seccomp.Notif, sc seccomp.Rule, raw string, rerr error) (ask func()) {
	reply := func(errno unix.Errno) { _ = l.n.Deny(n.ID, int32(errno)) }
	if rerr != nil {
		reply(unix.ENAMETOOLONG)
		return nil
	}
	q, errno := parseAdvance(raw)
	if errno != 0 {
		reply(errno)
		return nil
	}
	if m.kernel != nil {
		// As for other accesses, the rules are written for the root's
		// view only.
		ref := 0
		if m.procRoot {
			ref = l.root
		}
		if same, err := procfs.SameView(n.PID, ref); err == nil && !same {
			reply(unix.EINVAL)
			return nil
		}
	}
	root := "/"
	if m.procRoot {
		root = procfs.ProcRoot(n.PID)
	}
	t, err := procfs.Resolve(n.PID, root, procfs.AtFDCWD, q.path, true)
	if err != nil || t.Special != "" {
		reply(unix.EINVAL)
		return nil
	}
	obj := rules.Object{Path: &rules.PathObject{Path: t.Path}}
	if !l.n.IDValid(n.ID) {
		return nil
	}
	switch m.covered(q, t.Path) {
	case rules.Allow:
		reply(unix.EEXIST)
		return nil
	case rules.Deny:
		reply(unix.EPERM)
		return nil
	}
	if q.check {
		reply(unix.ENOMSG)
		return nil
	}
	return func() { m.askAdvance(l, n, sc.Name, q, obj, raw) }
}

// covered returns Allow if the current rules allow all q asks for on
// path, for as long as it asks; Deny if a rule denies path; Ask otherwise.
func (m *Monitor) covered(q advanceQuery, path string) rules.Verdict {
	now := m.now()
	rs := m.currentRules()
	v, id, ok := rules.Eval(rs, q.op, rules.Object{Path: &rules.PathObject{Path: path}}, now)
	if !ok || v == rules.Ask {
		return rules.Ask
	}
	if v == rules.Deny {
		return rules.Deny
	}
	for _, r := range rs {
		if r.ID != id {
			continue
		}
		if q.adv.Tree && (r.Object.Path == nil || !r.Object.Path.Tree) {
			return rules.Ask
		}
		// A request without a duration is for the rest of the session; a
		// check without one is about now. A grant ending within
		// advanceSlack of the end asked for covers it, so that asking
		// again right after a grant does not ask the user again.
		slack := min(q.adv.For/10, advanceSlack)
		if !r.Expires.IsZero() && !(q.check && q.adv.For == 0) && (q.adv.For == 0 || r.Expires.Before(now.Add(q.adv.For-slack))) {
			return rules.Ask
		}
	}
	if q.adv.Tree {
		// A deny or ask below path takes part of the tree away.
		for _, r := range rs {
			if r.Expired(now) || r.Ops&q.op == 0 || r.Verdict == rules.Allow || r.Object.Path == nil {
				continue
			}
			if rules.Under(r.Object.Path.Path, path) {
				return rules.Ask
			}
		}
	}
	return rules.Allow
}

// askAdvance opens a request for q (or joins the same one, for a restarted
// execve), waits for its verdict and answers n.
func (m *Monitor) askAdvance(l *listener, n seccomp.Notif, syscall string, q advanceQuery, obj rules.Object, raw string) {
	subject := buildSubject(n.PID, l.root)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	key := fmt.Sprintf("unique\x00%d", n.ID)
	if tgid := subject.Chain[0].PID; tgid > 0 {
		key = fmt.Sprintf("%d\x00advance\x00%s", tgid, raw)
	}
	r := m.byKey[key]
	if r != nil {
		r.waiters = append(r.waiters, waiter{l, n.ID})
	} else {
		adv := q.adv
		r = &request{
			pub: &Request{
				Syscall: syscall,
				Op:      q.op,
				Objects: []rules.Object{obj},
				Subject: subject,
				Advance: &adv,
			},
			key:     key,
			op:      q.op,
			obj:     obj,
			advance: true,
			waiters: []waiter{{l, n.ID}},
			done:    make(chan struct{}),
		}
		m.addLocked(r)
	}
	m.mu.Unlock()
	<-r.done
	errno := unix.EPERM
	switch {
	case r.why.Died:
		return
	case r.allow:
		errno = unix.EALREADY
	case r.timedOut:
		errno = unix.ETIMEDOUT
	}
	_ = l.n.Deny(n.ID, int32(errno))
}
