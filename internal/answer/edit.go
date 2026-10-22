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
// the rules removed and add the rules add, next being the rules after the
// change: editing the rules gives no more than answering. A deny or ask
// rule may be added or removed. An allow rule may be added when an
// "always" answer could give it (see Grantable), or when it narrows an
// allow rule removed with it (see narrows): an allow from the session's
// flags or policy can be narrowed, not widened.
func CheckRules(p Policy, add, removed, next []rules.Rule) error {
	for _, r := range add {
		if r.Verdict != rules.Allow || Grantable(p, r) || narrows(r, removed, next) {
			continue
		}
		return fmt.Errorf("%s: %w; allow a single program, destination or file, or a folder that a prompt would offer", r.Spec(), ErrTooWide)
	}
	return nil
}

// CheckTighten is CheckRules for a session that never prompts: no answer
// can allow anything, so its rules can only be tightened. Removing a deny
// or ask rule, or adding an allow rule that does not narrow one removed
// with it, fails with ErrTooWide.
func CheckTighten(add, removed, next []rules.Rule) error {
	for _, r := range removed {
		if r.Verdict != rules.Allow {
			return fmt.Errorf("removing %v: %w: this session never prompts", r, ErrTooWide)
		}
	}
	for _, r := range add {
		if r.Verdict == rules.Allow && !narrows(r, removed, next) {
			return fmt.Errorf("%s: %w: this session never prompts", r.Spec(), ErrTooWide)
		}
	}
	return nil
}

// narrows reports whether allow rule r allows nothing that an allow rule
// in removed did not, with the rules next: one of them covers r, and no
// ask rule of next that decided over it gives way to r. The deepest allow
// or ask decides (rules.Eval), so a narrower allow can be deeper than an
// ask rule the wider one was not: allow /work/** loses to ask
// /work/secret/**, allow /work/secret/key wins.
func narrows(r rules.Rule, removed, next []rules.Rule) bool {
	for _, o := range removed {
		if o.Covers(r) && !beatsAsk(r, o, next) {
			return true
		}
	}
	return false
}

// beatsAsk reports whether an ask rule of next, sharing ops and objects
// with r, wins over o but not over r.
func beatsAsk(r, o rules.Rule, next []rules.Rule) bool {
	dr, do := r.Object.Depth(), o.Object.Depth()
	for _, a := range next {
		if a.Verdict != rules.Ask || a.Ops&r.Ops == 0 || !overlaps(a.Object, r.Object) {
			continue
		}
		if da := a.Object.Depth(); do <= da && da < dr {
			return true
		}
	}
	return false
}

// overlaps reports whether a and b may select an object in common.
func overlaps(a, b rules.ObjectMatch) bool {
	switch {
	case a.Path != nil && b.Path != nil:
		x, y := a.Path, b.Path
		return x.Path == y.Path || (x.Tree && rules.Under(y.Path, x.Path)) || (y.Tree && rules.Under(x.Path, y.Path))
	case a.Proc != nil && b.Proc != nil:
		return *a.Proc == *b.Proc
	case a.Unknown || b.Unknown:
		return a.Unknown && b.Unknown
	}
	return a.OverlapsNet(b)
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
