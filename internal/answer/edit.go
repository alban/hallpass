// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package answer

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alban/hallpass/internal/rules"
)

// ErrTooWide is returned by CheckRules for a rule allowing more than an
// answer could.
var ErrTooWide = errors.New(`allows more than answering "always" could`)

// CheckRules checks that a client of a session with policy p may remove
// the rules removed and add the rules add: editing the rules gives no more
// than answering. A deny or ask rule may be added or removed. An allow rule
// may be added when an "always" answer could give it (see Grantable), or
// when it narrows an allow rule removed with it (see rules.Rule.Covers): an allow
// from the session's flags or policy can be narrowed, not widened.
func CheckRules(p Policy, add, removed []rules.Rule) error {
	for _, r := range add {
		if r.Verdict != rules.Allow || Grantable(p, r) || covered(r, removed) {
			continue
		}
		return fmt.Errorf("%v: %w; allow a single program, destination or file, or a folder that a prompt would offer", r, ErrTooWide)
	}
	return nil
}

// CheckTighten is CheckRules for a session that never prompts: no answer
// can allow anything, so its rules can only be tightened. Removing a deny
// or ask rule, or adding an allow rule that does not narrow one removed
// with it, fails with ErrTooWide.
func CheckTighten(add, removed []rules.Rule) error {
	for _, r := range removed {
		if r.Verdict != rules.Allow {
			return fmt.Errorf("removing %v: %w: this session never prompts", r, ErrTooWide)
		}
	}
	for _, r := range add {
		if r.Verdict == rules.Allow && !covered(r, removed) {
			return fmt.Errorf("%v: %w: this session never prompts", r, ErrTooWide)
		}
	}
	return nil
}

func covered(r rules.Rule, by []rules.Rule) bool {
	for _, o := range by {
		if o.Covers(r) {
			return true
		}
	}
	return false
}

// Grantable reports whether an "allow always" answer, with policy p, could
// give allow rule r, or a wider one: a path in a folder FolderFor offers,
// or such a folder; a program; a /proc file of the processes of a name;
// one address and port, or one unix socket.
func Grantable(p Policy, r rules.Rule) bool {
	o := r.Object
	if r.Ops == 0 {
		return true
	}
	switch {
	case o.Path != nil && len(o.Path.Args) > 0:
		return false
	case o.Path != nil && r.Ops&rules.OpExec != 0:
		return r.Ops == rules.OpExec && !o.Path.Tree
	case r.Ops&^rules.OpAll != 0:
		return false
	case o.Path != nil:
		probe := o.Path.Path
		if o.Path.Tree {
			// What a write below it would be offered.
			probe = filepath.Join(probe, "x")
		}
		f := p.FolderFor(probe)
		return f != "" && rules.Under(o.Path.Path, f)
	case o.Proc != nil:
		return true
	case o.Inet != nil:
		i := o.Inet
		return i.Prefix.IsValid() && i.Prefix.Bits() == i.Prefix.Addr().BitLen() && i.PortLo != 0 && i.PortLo == i.PortHi
	case o.Unix != nil:
		u := o.Unix
		return !u.Prefix && (u.Abstract || u.Path != "")
	}
	return false
}
