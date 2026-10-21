// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"net/url"
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
// would be needed. op is write (a path), exec (a program, path) or
// connect (dest, network destinations as rules.ParseNet reads them, but
// "all"). AdvanceDir+"release?op=...&path=..." removes the rules that
// granted that very request (AdvanceSet). The path never exists: without a
// monitor, the kernel fails the execve with ENOENT. The monitor never
// continues it, it answers with an errno:
//
//   - EEXIST: the rules already allow it (no request)
//   - EALREADY: a verdict allowed the request
//   - EPERM: a rule denies it, or a verdict denied the request
//   - ETIMEDOUT: denied because nobody answered in time
//     (Decision.TimedOut)
//   - EINVAL, ENAMETOOLONG: malformed or too long
//   - ENOSYS: the category asked for (write, exec, connect) is not
//     mediated (Config.Mediate): nothing would enforce a grant
//   - ENOMSG: (check only) a request would be needed
//   - ECANCELED: (release only) the grants were removed
//   - ESRCH: (release only) no grant of a request made in advance matches
//
// See docs/devel/monitor.md.
const AdvanceDir = "/proc/self/hallpass/"

// AdvanceSet is the rules.Rule.Set of the rules granting requests made in
// advance (Request.Grant). The workload may remove them (AdvanceDir
// release), and no other rule: only Allow rules may be added to it.
const AdvanceSet = "advance"

// advanceSlack bounds how much shorter than asked an existing grant may
// last and still cover an advance request (a tenth of it at most).
const advanceSlack = time.Minute

// Advance describes a Request the workload made in advance, before
// accessing Objects[0], or for network destinations, Net. Op is the
// operations asked for: rules.OpFiles, rules.OpExec or rules.OpNet.
type Advance struct {
	Tree   bool          // Objects[0] and everything below it
	For    time.Duration // how long the grant is asked for; 0: the rest of the session
	Reason string        // written by the workload: untrusted, display only
	// Net is the destinations asked for (rules.ParseNet) when Op is
	// rules.OpNet; Objects is then empty.
	Net rules.ObjectMatch
	// Writable: (exec) the rules let the workload write the program, or
	// a file below the folder, without asking, when it asked: a grant
	// lets it run what it writes there. Only known with files mediated.
	Writable bool
}

// Grant returns the rule that grants r, a request made in advance, until
// expires (zero: until removed): the same rule as the allow flags'
// (--allow-path, --allow-exec, --allow-net), in AdvanceSet.
func (r *Request) Grant(expires time.Time) rules.Rule {
	g := rules.Rule{Ops: grantOps(r.Op), Verdict: rules.Allow, Expires: expires, Set: AdvanceSet}
	if r.Advance.Net.IsNet() {
		g.Object = r.Advance.Net
	} else {
		g.Object = rules.ObjectMatch{Path: &rules.PathMatch{Path: r.Objects[0].Path.Path, Tree: r.Advance.Tree}}
	}
	return g
}

// grantOps returns the ops of the rule granting a request in advance for
// op: a file grant covers every file and network op, like a folder
// answer.
func grantOps(op rules.Op) rules.Op {
	switch op {
	case rules.OpExec, rules.OpNet:
		return op
	}
	return rules.OpAll
}

// advanceVerb is what an advance query does.
type advanceVerb int

const (
	verbRequest advanceVerb = iota
	verbCheck
	verbRelease
)

// advanceQuery is a parsed advance request.
type advanceQuery struct {
	verb advanceVerb
	op   rules.Op
	path string // write, exec: absolute and clean, not resolved yet
	adv  Advance
}

// scope is what q asks for, as a rule's object; path is resolved.
func (q advanceQuery) scope() rules.ObjectMatch {
	if q.op == rules.OpNet {
		return q.adv.Net
	}
	return rules.ObjectMatch{Path: &rules.PathMatch{Path: q.path, Tree: q.adv.Tree}}
}

// category is the mediated category q needs.
func (q advanceQuery) category() seccomp.Category {
	switch q.op {
	case rules.OpExec:
		return seccomp.Exec
	case rules.OpNet:
		return seccomp.Connect
	}
	return seccomp.Write
}

// parseAdvance parses raw, an execve path starting with AdvanceDir.
func parseAdvance(raw string) (advanceQuery, unix.Errno) {
	var q advanceQuery
	verb, query, _ := strings.Cut(strings.TrimPrefix(raw, AdvanceDir), "?")
	switch verb {
	case "request":
	case "check":
		q.verb = verbCheck
	case "release":
		q.verb = verbRelease
	default:
		return q, unix.EINVAL
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return q, unix.EINVAL
	}
	hasPath := false
	for k, v := range vals {
		if len(v) != 1 {
			return q, unix.EINVAL
		}
		switch k {
		case "op":
			switch v[0] {
			case "write":
				// The only file op rules can grant: every file op
				// (strict mode's rules have no finer ones).
				q.op = rules.OpFiles
			case "exec":
				q.op = rules.OpExec
			case "connect":
				// Connect and send, like an answer about either.
				q.op = rules.OpNet
			default:
				return q, unix.EINVAL
			}
		case "dest":
			m, err := rules.ParseNet(v[0])
			if err != nil || m.AnyNet {
				// "all" (unix sockets included) is mediation off,
				// not a scope: the user decides it with a flag.
				return q, unix.EINVAL
			}
			if m.Inet != nil && m.Inet.Prefix.IsValid() {
				// As in a rule (Monitor.check), so that a release
				// names the rule granted.
				m.Inet.Prefix = m.Inet.Prefix.Masked()
			}
			q.adv.Net = m
		case "path":
			hasPath = true
			pm, err := rules.ParsePathMatch(v[0])
			if err != nil {
				return q, unix.EINVAL
			}
			q.path, q.adv.Tree = pm.Path, pm.Tree
		case "for":
			d, err := time.ParseDuration(v[0])
			if err != nil || d <= 0 || q.verb == verbRelease {
				return q, unix.EINVAL
			}
			q.adv.For = d
		case "reason":
			if q.verb == verbRelease {
				return q, unix.EINVAL
			}
			q.adv.Reason = v[0]
		default:
			return q, unix.EINVAL
		}
	}
	// A path for files and programs, a destination for the network.
	if q.op == 0 || (q.op == rules.OpNet) != q.adv.Net.IsNet() || (q.op == rules.OpNet) == hasPath {
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
	if m.mediate&q.category() == 0 {
		reply(unix.ENOSYS)
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
	resolve := func(p string) (string, bool) {
		t, err := procfs.Resolve(n.PID, root, procfs.AtFDCWD, p, true)
		return t.Path, err == nil && t.Special == ""
	}
	var objs []rules.Object
	switch u := q.adv.Net.Unix; {
	case q.op != rules.OpNet:
		p, ok := resolve(q.path)
		if !ok {
			reply(unix.EINVAL)
			return nil
		}
		q.path = p
		objs = []rules.Object{{Path: &rules.PathObject{Path: p}}}
	case u != nil && !u.Abstract:
		// As a socket path in a rule: resolved like a file's.
		p, ok := resolve(u.Path)
		if !ok {
			reply(unix.EINVAL)
			return nil
		}
		q.adv.Net = rules.ObjectMatch{Unix: &rules.UnixMatch{Path: p, Prefix: u.Prefix}}
	}
	if !l.n.IDValid(n.ID) {
		return nil
	}
	if q.verb == verbRelease {
		reply(m.releaseGrants(l, n, q))
		return nil
	}
	switch m.covered(q) {
	case rules.Allow:
		reply(unix.EEXIST)
		return nil
	case rules.Deny:
		reply(unix.EPERM)
		return nil
	}
	if q.verb == verbCheck {
		reply(unix.ENOMSG)
		return nil
	}
	if q.op == rules.OpExec && m.mediate&seccomp.Write != 0 {
		q.adv.Writable = writable(m.currentRules(), q.path, q.adv.Tree, m.now())
	}
	return func() { m.askAdvance(l, n, sc.Name, q, objs, raw) }
}

// writable reports whether rs let the workload write path, or with tree a
// file below it, without asking.
func writable(rs []rules.Rule, path string, tree bool, now time.Time) bool {
	if v, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: path}}, now); ok && v == rules.Allow {
		return true
	}
	if tree {
		for _, r := range rs {
			if !r.Expired(now) && r.Verdict == rules.Allow && r.Ops&rules.OpWrite != 0 && r.Object.Path != nil && rules.Under(r.Object.Path.Path, path) {
				return true
			}
		}
	}
	return false
}

// covered returns Allow if the current rules allow all q asks for, for as
// long as it asks; Deny if a rule denies it (the path, or every
// destination asked for); Ask otherwise, also when the rules allow only
// part of it.
func (m *Monitor) covered(q advanceQuery) rules.Verdict {
	now := m.now()
	rs := m.currentRules()
	if q.op == rules.OpNet {
		return coveredNet(rs, q, now)
	}
	path := q.path
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
		if !lasts(r, q, now) {
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

// coveredNet is covered for network destinations: Allow if an allow
// covers all of them, for as long as q asks, and no deny or ask as
// specific takes part of them away; Deny if a deny covers all of them.
func coveredNet(rs []rules.Rule, q advanceQuery, now time.Time) rules.Verdict {
	want := q.adv.Net
	depth := -1 // of the most specific allow covering want
	partial := false
	var asks []rules.Rule
	for _, r := range rs {
		if r.Expired(now) || r.Ops&rules.OpNet == 0 || !r.Object.OverlapsNet(want) {
			continue
		}
		switch r.Verdict {
		case rules.Deny:
			if r.Object.CoversNet(want) {
				return rules.Deny
			}
			partial = true
		case rules.Ask:
			asks = append(asks, r)
		case rules.Allow:
			if r.Ops&rules.OpNet == rules.OpNet && r.Object.CoversNet(want) && lasts(r, q, now) {
				depth = max(depth, r.Object.Depth())
			}
		}
	}
	if partial || depth < 0 {
		return rules.Ask
	}
	for _, r := range asks {
		// The most specific rule decides, an ask on a tie: an ask
		// shallower than the allow does not apply.
		if r.Object.Depth() >= depth {
			return rules.Ask
		}
	}
	return rules.Allow
}

// lasts reports whether r, an allow, lasts as long as q asks. A request
// without a duration is for the rest of the session; a check without one
// is about now. A grant ending within advanceSlack of the end asked for
// covers it, so that asking again right after a grant does not ask the
// user again.
func lasts(r rules.Rule, q advanceQuery, now time.Time) bool {
	if r.Expires.IsZero() || (q.verb == verbCheck && q.adv.For == 0) {
		return true
	}
	slack := min(q.adv.For/10, advanceSlack)
	return q.adv.For != 0 && !r.Expires.Before(now.Add(q.adv.For-slack))
}

// releaseGrants removes the rules granting requests made in advance
// (AdvanceSet) for exactly what q names, and returns the errno answering
// it.
func (m *Monitor) releaseGrants(l *listener, n seccomp.Notif, q advanceQuery) unix.Errno {
	scope, ops := q.scope(), grantOps(q.op)
	now := m.now()
	var ids []uint64
	var gone []rules.Rule
	for _, r := range m.currentRules() {
		if r.Set == AdvanceSet && r.Verdict == rules.Allow && r.Ops == ops && !r.Expired(now) && sameScope(r.Object, scope) {
			ids = append(ids, r.ID)
			gone = append(gone, r)
		}
	}
	if len(ids) == 0 {
		return unix.ESRCH
	}
	if _, err := m.Apply(Decision{RemoveRules: ids, Client: releaseClient}); err != nil {
		m.warn("release of a grant made in advance: " + err.Error())
		return unix.EIO
	}
	m.mu.Lock()
	m.emitLocked(Event{Released: &Released{Rules: gone, Subject: buildSubject(n.PID, l.root)}})
	m.mu.Unlock()
	return unix.ECANCELED
}

// releaseClient is the Decision.Client of a release.
const releaseClient = "release"

// sameScope reports whether a and b, the objects of a grant made in
// advance, select the same things.
func sameScope(a, b rules.ObjectMatch) bool {
	switch {
	case a.Path != nil && b.Path != nil:
		return a.Path.Path == b.Path.Path && a.Path.Tree == b.Path.Tree && len(a.Path.Args)+len(b.Path.Args) == 0
	case a.IsNet() && b.IsNet():
		return a.NetString() == b.NetString()
	}
	return false
}

// askAdvance opens a request for q (or joins the same one, for a restarted
// execve), waits for its verdict and answers n. objs are its objects: the
// path, none for network destinations.
func (m *Monitor) askAdvance(l *listener, n seccomp.Notif, syscall string, q advanceQuery, objs []rules.Object, raw string) {
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
		var obj rules.Object
		if len(objs) > 0 {
			obj = objs[0]
		}
		r = &request{
			pub: &Request{
				Syscall: syscall,
				Op:      q.op,
				Objects: objs,
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
