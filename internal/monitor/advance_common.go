// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"time"

	"github.com/alban/hallpass/internal/rules"
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
