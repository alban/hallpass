// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package answer maps a prompt answer (once, temp, always, group, deny,
// never; grant for a request made in advance) to a monitor decision with a
// session's policy, and describes a request the way prompts show it. The
// CLI and the node agent share it, so an answer means the same in both.
package answer

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/programs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/ui"
	"golang.org/x/net/publicsuffix"
)

// maxParents bounds the parent chain shown in prompts.
const maxParents = 4

// OwnListenerNote is the prompt's note on a destination a process of the
// sandbox listens on.
const OwnListenerNote = "listener started inside the sandbox"

// Policy is what the mapping needs from the session's policy
// (*defaults.Defaults).
type Policy interface {
	// FolderFor is the folder an "allow temp/always" answer covers; ""
	// for none.
	FolderFor(path string) string
	// Warn labels a secret store, "" otherwise.
	Warn(path string) string
	// Group is the program group the program at path belongs to, offered
	// by an "allow group" answer.
	Group(path string) (programs.Group, bool)
}

// Find returns pending request id and the current rules; it fails with
// monitor.ErrClosed if the request is not pending.
func Find(m *monitor.Monitor, id uint64) (*monitor.Request, []rules.Rule, error) {
	pending, rs, _ := m.Snapshot()
	for _, r := range pending {
		if r.ID == id {
			return r, rs, nil
		}
	}
	return nil, nil, fmt.Errorf("request %d: %w", id, monitor.ErrClosed)
}

// Apply applies a, the answer of client who to req, with policy p: the
// folder of a grant, "never" as an exact deny. rs are the current rules.
// It fails with monitor.ErrClosed if req is no longer pending; the rules
// of a are applied anyway.
func Apply(m *monitor.Monitor, p Policy, req *monitor.Request, a ui.Answer, rs []rules.Rule, who string) error {
	a = Request(p, req, 0).Effective(a)
	d := monitor.Decision{Client: who}
	allow := false
	var obj rules.Object
	if len(req.Objects) > 0 {
		// None for a request made in advance for network destinations.
		obj = req.Objects[0]
	}
	ops := answerOps(req.Op)
	switch a {
	case ui.AnswerGrant:
		allow = true
		var expires time.Time
		if req.Advance.For > 0 {
			expires = time.Now().Add(req.Advance.For)
		}
		d.AddRules = append(d.AddRules, req.Grant(expires))
	case ui.AnswerTimeout:
		d.TimedOut = true
	case ui.AnswerAllowOnce:
		allow = true
	case ui.AnswerAllowTemp:
		allow = true
		grant(p, &d, rs, ops, obj, req.Names, time.Now().Add(ui.TempGrant))
	case ui.AnswerAllowAlways:
		allow = true
		grant(p, &d, rs, ops, obj, req.Names, time.Time{})
	case ui.AnswerAllowDomain:
		// Valid: a connection to an address with names.
		allow = true
		_, m, _ := hostScopes(obj, req.Names)
		addGrant(&d, rs, ops, m, time.Time{})
	case ui.AnswerAllowGroup:
		// Valid: an exec of a program of a group.
		allow = true
		g, _ := p.Group(obj.Path.Path)
		d.AddRules = defaults.GroupRules(g, rs, "")
	case ui.AnswerNever:
		d.AddRules = append(d.AddRules, rules.Rule{Ops: ops, Verdict: rules.Deny, Object: exact(obj)})
	}
	d.Verdicts = []monitor.Verdict{{Request: req.ID, Allow: allow}}
	_, err := m.Apply(d)
	if errors.Is(err, monitor.ErrClosed) {
		// Its task died, another client answered, or the monitor
		// closed: keep the rules.
		d.Verdicts = nil
		if len(d.AddRules)+len(d.RemoveRules) > 0 {
			_, _ = m.Apply(d)
		}
		return err
	}
	if err != nil {
		// The rules failed (strict mode): give the verdict alone. A
		// grant is its rule: without it, the program would go ahead
		// and be asked anyway, so it is denied.
		if a == ui.AnswerGrant {
			d.Verdicts[0].Allow = false
		}
		if _, err2 := m.Apply(monitor.Decision{Verdicts: d.Verdicts, Client: who}); err2 != nil {
			return errors.Join(err, err2)
		}
	}
	return err
}

// answerOps returns the ops the rules of an answer to a request about op
// cover: an exec answer covers running the program only, a file or network
// one every file and network op.
func answerOps(op rules.Op) rules.Op {
	if op&rules.OpExec != 0 {
		return rules.OpExec
	}
	if op&rules.OpHTTP != 0 {
		return rules.OpHTTP
	}
	return rules.OpAll
}

// grant adds to d the rule an "allow temp/always" answer gives obj for
// ops: its folder (the program itself for an exec), its kind of /proc
// file, or for a network address with names, its first name and port.
func grant(p Policy, d *monitor.Decision, rs []rules.Rule, ops rules.Op, obj rules.Object, names []string, expires time.Time) {
	var m rules.ObjectMatch
	switch {
	case obj.Path != nil && ops == rules.OpExec:
		m.Path = &rules.PathMatch{Path: obj.Path.Path}
	case obj.Path != nil:
		folder := p.FolderFor(obj.Path.Path)
		if folder == "" {
			return
		}
		m.Path = &rules.PathMatch{Path: folder, Tree: true}
	case obj.Proc != nil:
		m.Proc = &rules.ProcMatch{Name: obj.Proc.Name, Comm: comm(obj.Proc)}
	case obj.HTTP != nil:
		m = exact(obj)
	case obj.IsNet():
		if h, _, ok := hostScopes(obj, names); ok {
			m = h
			break
		}
		// The address alone: no subject or subtree answers yet.
		m = rules.ExactNet(obj)
	default:
		return
	}
	addGrant(d, rs, ops, m, expires)
}

// addGrant adds to d an allow of m for ops until expires. A grant never
// shrinks: an existing grant on the same scope lasting longer is kept.
func addGrant(d *monitor.Decision, rs []rules.Rule, ops rules.Op, m rules.ObjectMatch, expires time.Time) {
	for _, r := range rs {
		if r.Set != "" || r.Verdict != rules.Allow || r.Ops != ops || !sameMatch(r.Object, m) {
			continue
		}
		if r.Expires.IsZero() || (!expires.IsZero() && !expires.After(r.Expires)) {
			return
		}
		d.RemoveRules = append(d.RemoveRules, r.ID)
	}
	d.AddRules = append(d.AddRules, rules.Rule{Ops: ops, Verdict: rules.Allow, Object: m, Expires: expires})
}

// hostScopes returns what the answers to a connection to inet object
// obj, whose address has names (most recent first), cover: "always" its
// first name and port ("api.github.com:443"), "domain" the names below
// its registrable domain ("*.github.com:443"), from the public suffix
// list: no list of services in hallpass. ok is false without names;
// domain is zero when the name is the registrable domain itself, or has
// none (a public suffix, a single label).
func hostScopes(obj rules.Object, names []string) (always, domain rules.ObjectMatch, ok bool) {
	if obj.Inet == nil || len(names) == 0 {
		return always, domain, false
	}
	name, _, err := rules.ParseHost(names[0])
	if err != nil {
		return always, domain, false
	}
	port := obj.Inet.Addr.Port()
	always = rules.ObjectMatch{Inet: &rules.InetMatch{Host: name, PortLo: port, PortHi: port}}
	if reg, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && reg != name {
		domain = rules.ObjectMatch{Inet: &rules.InetMatch{Host: reg, HostSuffix: true, PortLo: port, PortHi: port}}
	}
	return always, domain, true
}

// exact matches obj alone, for "never".
func exact(obj rules.Object) rules.ObjectMatch {
	switch {
	case obj.Path != nil:
		return rules.ObjectMatch{Path: &rules.PathMatch{Path: obj.Path.Path}}
	case obj.Proc != nil:
		return rules.ObjectMatch{Proc: &rules.ProcMatch{Name: obj.Proc.Name, Comm: comm(obj.Proc)}}
	case obj.IsNet():
		return rules.ExactNet(obj)
	case obj.HTTP != nil:
		// A '*' in the path reads as a glob: "never" then denies a
		// little more; "always" is not offered (Request).
		return rules.ObjectMatch{HTTP: &rules.HTTPMatch{Methods: []string{obj.HTTP.Method}, Host: obj.HTTP.Host, Path: obj.HTTP.Path}}
	}
	return rules.ObjectMatch{Unknown: true}
}

func sameMatch(a, b rules.ObjectMatch) bool {
	switch {
	case a.Path != nil && b.Path != nil:
		return a.Path.Path == b.Path.Path && a.Path.Tree == b.Path.Tree && len(a.Path.Args)+len(b.Path.Args) == 0
	case a.Proc != nil && b.Proc != nil:
		return *a.Proc == *b.Proc
	case a.HTTP != nil || b.HTTP != nil:
		return a.HTTP != nil && b.HTTP != nil && a.HTTP.String() == b.HTTP.String()
	case a.IsNet() || b.IsNet():
		return a.IsNet() && b.IsNet() && a.NetString() == b.NetString()
	}
	return a.Unknown && b.Unknown
}

func comm(p *rules.ProcObject) string {
	if len(p.Target.Chain) == 0 {
		return ""
	}
	return p.Target.Chain[0].Comm
}

// Request describes req for an asker, with policy p. waiting is the number
// of other requests queued behind it.
func Request(p Policy, req *monitor.Request, waiting int) ui.Request {
	r := ui.Request{Op: req.Op.String(), Waiting: max(0, waiting)}
	if ch := req.Subject.Chain; len(ch) > 0 {
		r.Exe, r.PID, r.Cmdline = ch[0].Exe, uint32(ch[0].TID), ch[0].Cmdline
		for _, t := range ch[1:min(len(ch), maxParents+1)] {
			r.Parents = append(r.Parents, t.Comm)
		}
	}
	if a := req.Advance; a != nil {
		r.Advance, r.For, r.Reason = true, a.For, a.Reason
		switch {
		case a.Net.IsNet():
			r.Op, r.Path = "connect to", a.Net.NetString()
		case a.Net.HTTP != nil:
			r.Op, r.Path = "send", a.Net.HTTP.String()
		case req.Op == rules.OpExec:
			r.Op = "exec"
			if a.Writable {
				r.Warn = "writable from inside the sandbox: a grant lets it run what it writes there"
			}
		default:
			r.Op = "write"
			if w := p.Warn(req.Objects[0].Path.Path); w != "" {
				r.Warn = w + " — secret store"
			}
		}
		if !a.Net.IsNet() && a.Net.HTTP == nil {
			r.Path = req.Objects[0].Path.Path
			if a.Tree {
				r.Path = strings.TrimSuffix(r.Path, "/") + "/**"
			}
		}
		return r
	}
	switch obj := req.Objects[0]; {
	case obj.Path != nil && req.Op&rules.OpExec != 0:
		// Answers cover this program, not its folder: a grant on
		// /usr/bin would allow every program there.
		r.Path = obj.Path.Path
		r.Scope, r.Never = r.Path, "this program"
		if g, ok := p.Group(r.Path); ok {
			r.ProgramGroup = g.String()
		}
	case obj.Path != nil:
		r.Path = obj.Path.Path
		r.Scope = p.FolderFor(r.Path)
		r.Never = "this path"
		if w := p.Warn(r.Path); w != "" {
			r.Warn = w + " — secret store"
		}
	case obj.Proc != nil:
		r.Path = ProcPath(obj.Proc)
		what := fmt.Sprintf("%s of %q processes outside the sandbox", obj.Proc.Name, comm(obj.Proc))
		r.Scope, r.Never = what, what
	case obj.HTTP != nil:
		// "curl wants to POST https://api.github.com/...": answers
		// cover this method on this URL path.
		r.Op, r.Path = obj.HTTP.Method, obj.HTTP.URL()
		r.Scope, r.Never = obj.HTTP.Method+" "+r.Path, obj.HTTP.Method+" "+r.Path
		if strings.Contains(obj.HTTP.Path, "*") || strings.HasSuffix(obj.HTTP.Path, "/**") {
			// The rule would read it as a glob, and allow more.
			r.Scope = ""
		}
	case obj.Inet != nil:
		// "connect to 1.2.3.4:443": answers cover every protocol
		// (rules.ExactNet), so the protocol is a detail.
		r.Op += " to"
		r.Path = obj.Inet.Addr.String()
		r.Detail = rules.ProtoName(obj.Inet.Proto)
		// The names are display only: answers cover the address.
		r.HostNames = strings.Join(req.Names[:min(len(req.Names), 2)], ", ")
		if r.HostNames == "" {
			r.ReverseNames = strings.Join(req.UnverifiedNames[:min(len(req.UnverifiedNames), 2)], ", ")
		}
		r.Scope, r.Never = r.Path, r.Path
		if always, domain, ok := hostScopes(obj, req.Names); ok {
			// Answers by name: the address is one of many.
			r.Scope = always.NetString()
			if domain.Inet != nil {
				r.Domain = domain.NetString()
			}
		}
		if obj.Inet.OwnListener {
			r.Note = OwnListenerNote
		}
	case obj.Unix != nil:
		r.Op += " to"
		r.Path = obj.Unix.String()
		r.Scope, r.Never = r.Path, r.Path
		if obj.Unix.OwnListener {
			r.Note = OwnListenerNote
		}
	default:
		// Allowing it skips every rule, including the denies, and a
		// process can make its path unreadable on purpose: so only "once"
		// is offered, never a lasting grant.
		r.Path = "(unknown path)"
		r.Never = "all unknown paths"
		r.Warn = "Unknown path — hallpass could not read it (" + obj.Unknown.Error() + ")"
	}
	return r
}

// Released names grants the workload gave back (monitor.Released) as its
// requests in advance did, e.g. "write /w/**, connect to tcp:10.0.0.0/8".
func Released(rs []rules.Rule) string {
	var names []string
	for _, r := range rs {
		o := r.Object
		switch {
		case o.IsNet():
			names = append(names, "connect to "+o.NetString())
		case o.Path != nil:
			op := "write "
			if r.Ops == rules.OpExec {
				op = "exec "
			}
			p := o.Path.Path
			if o.Path.Tree {
				p = strings.TrimSuffix(p, "/") + "/**"
			}
			names = append(names, op+p)
		}
	}
	return strings.Join(names, ", ")
}

// ProcPath names a /proc object, e.g. /proc/42/mem.
func ProcPath(p *rules.ProcObject) string {
	tid := 0
	if len(p.Target.Chain) > 0 {
		tid = p.Target.Chain[0].TID
	}
	return fmt.Sprintf("/proc/%d/%s", tid, p.Name)
}
