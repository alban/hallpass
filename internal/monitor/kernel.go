// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"

	"github.com/alban/hallpass/internal/lsm"
	"github.com/alban/hallpass/internal/rules"
)

// toLSM translates r for the kernel. The BPF programs have no operations
// and see no unreadable paths: a file rule must cover every file op, a
// network rule every network op, and an exec rule is for exec alone and
// cannot ask (a program no rule allows is asked anyway). An ask rule
// denies what it matches in the kernel, but for more specific allows and
// the one-time grants of prompts. Network rules go to net, but for unix
// socket paths (a Rule with Net).
func toLSM(r rules.Rule, net *lsm.NetRules) (*lsm.Rule, *lsm.ProcRule, error) {
	deny, ask := r.Verdict == rules.Deny, r.Verdict == rules.Ask
	if o := r.Object; o.IsNet() {
		if r.Ops&rules.OpNet != rules.OpNet {
			return nil, nil, fmt.Errorf("%w: %+v", ErrUnsupported, r)
		}
		switch {
		case o.AnyNet:
			net.Inet = append(net.Inet, lsm.InetRule{Deny: deny, Ask: ask, Expires: r.Expires})
			net.AnyUnix = append(net.AnyUnix, lsm.UnixAnyRule{Deny: deny, Ask: ask, Expires: r.Expires})
		case o.OwnListener:
			if deny || ask {
				return nil, nil, fmt.Errorf("%w: %+v", ErrUnsupported, r)
			}
			// Unlike other rules, it does not expire.
			net.OwnListeners = true
		case o.Inet != nil:
			net.Inet = append(net.Inet, lsm.InetRule{Prefix: o.Inet.Prefix, Proto: o.Inet.Proto, PortLo: o.Inet.PortLo, PortHi: o.Inet.PortHi,
				Deny: deny, Ask: ask, Depth: uint16(o.Depth()), Expires: r.Expires})
		case o.Unix.Abstract:
			net.Abstract = append(net.Abstract, lsm.AbstractRule{Name: o.Unix.Name, Prefix: o.Unix.Prefix, Deny: deny, Ask: ask, Expires: r.Expires})
		default:
			return &lsm.Rule{Path: o.Unix.Path, Tree: o.Unix.Prefix, Deny: deny, Ask: ask, Net: true, Expires: r.Expires}, nil, nil
		}
		return nil, nil, nil
	}
	if r.Ops&rules.OpExec != 0 {
		// Programs, by path; never an unknown path or a /proc file.
		p := r.Object.Path
		if ask || r.Ops != rules.OpExec || p == nil || len(p.Args) > 0 {
			return nil, nil, fmt.Errorf("%w: %+v", ErrUnsupported, r)
		}
		return &lsm.Rule{Path: p.Path, Tree: p.Tree, Deny: deny, Exec: true, Expires: r.Expires}, nil, nil
	}
	if r.Object.Unknown || r.Ops&rules.OpFiles != rules.OpFiles {
		return nil, nil, fmt.Errorf("%w: %+v", ErrUnsupported, r)
	}
	if p := r.Object.Proc; p != nil {
		return nil, &lsm.ProcRule{Name: p.Name, Comm: p.Comm, Deny: deny, Ask: ask, Expires: r.Expires}, nil
	}
	p := r.Object.Path
	return &lsm.Rule{Path: p.Path, Tree: p.Tree, Deny: deny, Ask: ask, Expires: r.Expires}, nil, nil
}

// syncLocked makes the kernel's rules rs. kmu must be held.
func (m *Monitor) syncLocked(rs []rules.Rule) error {
	var paths []lsm.Rule
	var procs []lsm.ProcRule
	var net lsm.NetRules
	for _, r := range rs {
		p, pr, err := toLSM(r, &net)
		if err != nil {
			return err
		}
		if p != nil {
			paths = append(paths, *p)
		}
		if pr != nil {
			procs = append(procs, *pr)
		}
	}
	if err := m.kernel.Sync(paths, procs); err != nil {
		return err
	}
	return m.kernel.SyncNet(net)
}

// kernelEvent reports a decision of the BPF programs.
func (m *Monitor) kernelEvent(e lsm.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.decided == 0 {
		return
	}
	obj := rules.Object{Path: &rules.PathObject{Path: e.Path}}
	switch {
	case e.Inet != nil:
		obj = rules.Object{Inet: &rules.InetObject{Proto: e.Inet.Proto, Addr: e.Inet.Addr}}
	case e.Unix != nil:
		obj = rules.Object{Unix: &rules.UnixObject{Abstract: e.Unix.Abstract, Name: e.Unix.Name, Path: e.Unix.Path}}
	}
	m.emitLocked(Event{Decided: &Decided{
		Time:    m.now(),
		Syscall: e.Op,
		Op:      lsmOp(e.Op),
		Objects: []rules.Object{obj},
		Subject: rules.Subject{Chain: []rules.Task{{PID: int(e.PID), TID: int(e.PID), Comm: e.Comm}}},
		Allowed: e.Allowed,
		Why:     []Reason{{}},
		Source:  SourceLSM,
	}})
}

func lsmOp(name string) rules.Op {
	switch name {
	case "open":
		return rules.OpWrite
	case "create":
		return rules.OpCreate
	case "mkdir":
		return rules.OpMkdir
	case "rmdir", "unlink":
		return rules.OpDelete
	case "symlink":
		return rules.OpSymlink
	case "link":
		return rules.OpLink
	case "rename":
		return rules.OpRename
	case "truncate":
		return rules.OpTruncate
	case "connect":
		return rules.OpConnect
	case "send":
		return rules.OpSend
	case "exec":
		return rules.OpExec
	}
	return rules.OpAll
}
