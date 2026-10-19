// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/rules"
)

// The tests in this file compare rules.Eval, lite mode's decision, with
// what the kernel decides from the maps the supervisor fills: the BPF
// lookups are replayed in Go (walkBits mirrors walk and node_bits). Lite
// mode allows what Eval allows; strict mode allows without a grant what
// the maps allow.

const (
	bitAllow = 1
	bitDeny  = 2
	bitAsk   = 4
)

// nodeBits is node_bits.
func nodeBits(v hallpassRuleVal, exact, net bool, now uint64, b int) int {
	allowTree, allowExact, askTree, askExact := v.AllowTree, v.AllowExact, v.AskTree, v.AskExact
	deny := v.DenyTree != 0 || (exact && v.DenyExact != 0)
	if net {
		allowTree, allowExact, askTree, askExact = v.NetAllowTree, v.NetAllowExact, v.NetAskTree, v.NetAskExact
		deny = v.NetDenyTree != 0 || (exact && v.NetDenyExact != 0)
	}
	ask := func() { b = b&^bitAllow | bitAsk }
	if deny {
		b |= bitDeny
	}
	if allowTree > now {
		b |= bitAllow
	}
	if askTree > now {
		ask()
	}
	if exact {
		if allowExact > now {
			b |= bitAllow
		}
		if askExact > now {
			ask()
		}
	}
	return b
}

// walkBits is walk, without grants, for the file lc.
func walkBits(nodes map[nodeKey]hallpassRuleVal, lc loc, net bool, now uint64) int {
	var comps []string
	for _, c := range strings.Split(lc.path, "/") {
		if c != "" {
			comps = append(comps, c)
		}
	}
	cookie := rootCookie | uint64(lc.dev)
	b := 0
	if v, ok := nodes[nodeKey{cookie, ""}]; ok {
		b = nodeBits(v, len(comps) == 0, net, now, b)
	}
	for i, c := range comps {
		v, ok := nodes[nodeKey{cookie, c}]
		if !ok {
			break
		}
		b = nodeBits(v, i == len(comps)-1, net, now, b)
		cookie = v.Cookie
	}
	return b
}

const askMountinfo = `22 1 8:1 / / rw - ext4 /dev/sda1 rw
25 22 0:31 /home /home rw - btrfs /dev/sda2 rw,subvol=/home
27 25 0:40 / /home/u/mnt rw - vfat /dev/sdb1 rw
`

// testSession is a session with no kernel, to compute its maps.
func testSession() *Session {
	return &Session{l: &LSM{cookies: map[nodeKey]uint64{}, next: 1}, inRoot: "/nonexistent-hallpass-test"}
}

// pick returns a random subset of cands.
func pick[T any](r *rand.Rand, cands []T, n int) []T {
	var out []T
	for range n {
		out = append(out, cands[r.IntN(len(cands))])
	}
	return out
}

func verdicts() []rules.Verdict { return []rules.Verdict{rules.Allow, rules.Deny, rules.Ask} }

// TestAskPathsMatchEval: for random sets of path rules, files and unix
// sockets, the kernel allows what Eval allows, and nothing else. Mounts
// are on /home and /home/u/mnt: rules above a mount point reach the root
// node of the filesystem mounted there, with other depths.
func TestAskPathsMatchEval(t *testing.T) {
	mounts, err := parseMounts(strings.NewReader(askMountinfo))
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"/", "/home", "/home/u", "/home/u/.env", "/home/u/proj", "/home/u/proj/secret", "/home/u/proj/secret/pub", "/home/u/mnt", "/home/u/mnt/x", "/etc"}
	var cands []rules.Rule
	for _, p := range paths {
		for _, tree := range []bool{false, true} {
			for _, v := range verdicts() {
				cands = append(cands, rules.Rule{Ops: rules.OpAll, Verdict: v, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: p, Tree: tree}}})
			}
		}
	}
	objects := append(paths, "/home/u/x", "/home/u/.env/x", "/home/u/proj/secret/f", "/home/u/proj/secret/pub/f", "/home/u/mnt/x/y", "/home/u/mnt/z", "/etc/passwd")
	r := rand.New(rand.NewPCG(1, 2))
	now := time.Now()
	for i := range 3000 {
		rs := pick(r, cands, 1+r.IntN(6))
		for _, net := range []bool{false, true} {
			var lrs []Rule
			for _, x := range rs {
				lrs = append(lrs, Rule{Path: x.Object.Path.Path, Tree: x.Object.Path.Tree, Deny: x.Verdict == rules.Deny, Ask: x.Verdict == rules.Ask, Net: net})
			}
			s := testSession()
			s.lastRules = lrs
			nodes := s.ruleNodes(mounts, expiryClock())
			mono := monotonic()
			for _, o := range objects {
				obj := rules.Object{Path: &rules.PathObject{Path: o}}
				op := rules.OpWrite
				if net {
					obj = rules.Object{Unix: &rules.UnixObject{Path: o}}
					op = rules.OpConnect
				}
				ev, _, ok := rules.Eval(netRules(rs, net), op, obj, now)
				want := ok && ev == rules.Allow
				b := walkBits(nodes, locate(mounts, o, false, 0)[0], net, mono)
				if got := b&(bitAllow|bitDeny) == bitAllow; got != want {
					t.Fatalf("%d: rules %s, net %v: %s allowed %v, want %v (Eval %v %v)", i, describe(rs), net, o, got, want, ev, ok)
				}
			}
		}
	}
}

// netRules turns path rules into unix socket rules, with net.
func netRules(rs []rules.Rule, net bool) []rules.Rule {
	out := make([]rules.Rule, len(rs))
	for i, r := range rs {
		r.Ops = rules.OpFiles
		if net {
			p := r.Object.Path
			r.Ops = rules.OpNet
			r.Object = rules.ObjectMatch{Unix: &rules.UnixMatch{Path: p.Path, Prefix: p.Tree}}
		}
		out[i] = r
	}
	return out
}

func describe(rs []rules.Rule) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.Verdict.String())
		b.WriteByte(' ')
		switch {
		case r.Object.Path != nil:
			b.WriteString(r.Object.Path.Path)
			if r.Object.Path.Tree {
				b.WriteString("/**")
			}
		default:
			b.WriteString(r.Object.NetString())
		}
		b.WriteString("; ")
	}
	return b.String()
}

// TestAskNodeLevels checks the rules of one node reached by rules of
// different depths, through mounts.
func TestAskNodeLevels(t *testing.T) {
	type rule struct {
		path       string
		tree, deny bool
		ask        bool
	}
	for _, c := range []struct {
		name         string
		rules        []rule
		target, desc bool // allowed: the node itself, and below it
	}{
		{"tie", []rule{{path: "/a", tree: true}, {path: "/b", tree: true, ask: true}}, false, false},
		{"deeper allow", []rule{{path: "/a/b", tree: true}, {path: "/a", tree: true, ask: true}}, true, true},
		{"deeper ask", []rule{{path: "/a", tree: true}, {path: "/a/b", tree: true, ask: true}}, false, false},
		{"deeper exact allow", []rule{{path: "/a/b"}, {path: "/a", tree: true, ask: true}}, true, false},
		{"shallower exact allow", []rule{{path: "/a"}, {path: "/a/b", tree: true, ask: true}}, false, false},
		{"deeper tree allow, exact ask", []rule{{path: "/a/b", tree: true}, {path: "/a", ask: true}}, true, true},
		{"exact ask", []rule{{path: "/a", tree: true}, {path: "/a", ask: true}}, false, true},
		{"exact tie", []rule{{path: "/a"}, {path: "/a", ask: true}}, false, true},
		{"deny", []rule{{path: "/a/b", tree: true}, {path: "/a", tree: true, deny: true}}, false, false},
	} {
		lv := newNodeLevels()
		for _, r := range c.rules {
			Rule{Path: r.path, Tree: r.tree, Deny: r.deny, Ask: r.ask}.addTo(lv, forever)
		}
		var v hallpassRuleVal
		lv.fill(&v)
		target := nodeBits(v, true, false, 1, bitAllow)
		desc := nodeBits(v, false, false, 1, bitAllow)
		if got := target&(bitAllow|bitDeny) == bitAllow; got != c.target {
			t.Errorf("%s: node allowed %v, want %v (%+v)", c.name, got, c.target, v)
		}
		if got := desc&(bitAllow|bitDeny) == bitAllow; got != c.desc {
			t.Errorf("%s: below allowed %v, want %v (%+v)", c.name, got, c.desc, v)
		}
	}
}
