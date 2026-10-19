// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
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

// netBits is net_bits.
func netBits(deny, allow, ask int) int {
	switch {
	case allow > ask:
		return deny | bitAllow
	case ask >= 0:
		return deny | bitAsk
	}
	return deny
}

// prefixOf reports whether the first bits of a and b are the same.
func prefixOf(a, b []byte, bits int) bool {
	for i := 0; i < bits; i++ {
		if a[i/8]>>(7-i%8)&1 != b[i/8]>>(7-i%8)&1 {
			return false
		}
	}
	return true
}

// inetBits is the inet_rules lookup and inet_rules_of.
func inetBits(trie map[hallpassInetKey]hallpassInetVal, a netip.Addr, proto, port uint16, now uint64) int {
	addr := a.As16()
	var best *hallpassInetKey
	for k := range trie {
		if prefixOf(k.Addr[:], addr[:], int(k.Prefixlen)-32) && (best == nil || k.Prefixlen > best.Prefixlen) {
			best = &k
		}
	}
	if best == nil {
		return 0
	}
	deny, allow, ask := 0, -1, -1
	for _, e := range trie[*best].E {
		switch {
		case e.Expiry == 0 && e.Deny == 0,
			e.Proto != 0 && e.Proto != proto,
			(e.PortLo != 0 || e.PortHi != 0) && (port < e.PortLo || port > e.PortHi):
		case e.Deny != 0:
			deny = bitDeny
		case e.Expiry <= now:
		case e.Ask != 0:
			ask = max(ask, int(e.Depth))
		default:
			allow = max(allow, int(e.Depth))
		}
	}
	return netBits(deny, allow, ask)
}

func asBytes(s []int8) []byte {
	b := make([]byte, len(s))
	for i, c := range s {
		b[i] = byte(c)
	}
	return b
}

// abstractBits is the abstract_rules lookup and abstract_rules_of, then
// the rules for every unix socket of check_unix.
func abstractBits(trie map[hallpassAbstractKey]hallpassAbstractVal, cfg hallpassSessionCfg, name string, now uint64) int {
	var key hallpassAbstractKey
	copyName(key.Name[:], name)
	var best *hallpassAbstractKey
	for k := range trie {
		bits := int(k.Prefixlen) - 32
		if bits <= 8*len(name) && prefixOf(asBytes(k.Name[:]), asBytes(key.Name[:]), bits) && (best == nil || k.Prefixlen > best.Prefixlen) {
			best = &k
		}
	}
	b := 0
	if best != nil {
		deny, allow, ask := 0, -1, -1
		for _, e := range trie[*best].E {
			switch {
			case e.Expiry == 0 && e.Deny == 0,
				e.Exact != 0 && int(e.Len) != len(name):
			case e.Deny != 0:
				deny = bitDeny
			case e.Expiry <= now:
			case e.Ask != 0:
				ask = max(ask, int(e.Len))
			default:
				allow = max(allow, int(e.Len))
			}
		}
		b = netBits(deny, allow, ask)
	}
	if cfg.AnyUnixDeny != 0 {
		b |= bitDeny
	}
	if b&bitAsk == 0 && cfg.AnyUnixAsk <= now && cfg.AnyUnixAllow > now {
		b |= bitAllow
	}
	return b
}

// lsmNet is the monitor's translation of network rules (toLSM).
func lsmNet(rs []rules.Rule) NetRules {
	var n NetRules
	for _, r := range rs {
		deny, ask, o := r.Verdict == rules.Deny, r.Verdict == rules.Ask, r.Object
		switch {
		case o.AnyNet:
			n.Inet = append(n.Inet, InetRule{Deny: deny, Ask: ask, Expires: r.Expires})
			n.AnyUnix = append(n.AnyUnix, UnixAnyRule{Deny: deny, Ask: ask, Expires: r.Expires})
		case o.Inet != nil:
			n.Inet = append(n.Inet, InetRule{Prefix: o.Inet.Prefix, Proto: o.Inet.Proto, PortLo: o.Inet.PortLo, PortHi: o.Inet.PortHi, Deny: deny, Ask: ask, Depth: uint16(o.Depth()), Expires: r.Expires})
		case o.Unix != nil:
			n.Abstract = append(n.Abstract, AbstractRule{Name: o.Unix.Name, Prefix: o.Unix.Prefix, Deny: deny, Ask: ask, Expires: r.Expires})
		}
	}
	return n
}

// TestAskNetMatchEval: for random sets of inet and abstract unix rules,
// the kernel allows what Eval allows, and nothing else.
func TestAskNetMatchEval(t *testing.T) {
	var inet []rules.ObjectMatch
	for _, s := range []string{"", "0.0.0.0/0", "::/0", "::ffff:0:0/96", "10.0.0.0/8", "10.0.0.1/32", "2001:db8::/32", "2001:db8::1/128"} {
		var p netip.Prefix
		if s != "" {
			p = netip.MustParsePrefix(s)
		}
		inet = append(inet,
			rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: p}},
			rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: p, PortLo: 22, PortHi: 22}},
			rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: p, Proto: 6}},
			rules.ObjectMatch{Inet: &rules.InetMatch{Prefix: p, Proto: 17, PortLo: 20, PortHi: 30}})
	}
	var abs []rules.ObjectMatch
	for _, n := range []string{"", "a", "ab", "abc", "b"} {
		for _, p := range []bool{false, true} {
			abs = append(abs, rules.ObjectMatch{Unix: &rules.UnixMatch{Abstract: true, Name: n, Prefix: p}})
		}
	}
	anyNet := rules.ObjectMatch{AnyNet: true}
	inet, abs = append(inet, anyNet), append(abs, anyNet)

	type dest struct {
		addr  string
		proto uint16
	}
	dests := []dest{{"10.0.0.1:22", 6}, {"10.0.0.1:25", 17}, {"10.0.0.1:80", 6}, {"10.0.0.2:22", 17}, {"192.168.1.1:22", 6},
		{"[2001:db8::1]:22", 6}, {"[2001:db8::1]:443", 17}, {"[2001:db8::2]:25", 17}, {"[::1]:22", 6}}
	names := []string{"", "a", "ab", "abc", "abcd", "b", "x"}

	rnd := rand.New(rand.NewPCG(3, 4))
	now := time.Now()
	soon := now.Add(time.Hour)
	for i := range 5000 {
		for _, cands := range [][]rules.ObjectMatch{inet, abs} {
			var rs []rules.Rule
			for _, o := range pick(rnd, cands, 1+rnd.IntN(6)) {
				r := rules.Rule{Ops: rules.OpNet, Object: o, Verdict: verdicts()[rnd.IntN(3)]}
				if rnd.IntN(4) == 0 {
					r.Expires = soon
				}
				rs = append(rs, r)
			}
			n := lsmNet(rs)
			expiry := expiryClock()
			mono := monotonic()
			it, err := inetTrie(1, n.Inet, expiry)
			if err != nil {
				t.Fatal(err)
			}
			at, err := abstractTrie(1, n.Abstract, expiry)
			if err != nil {
				t.Fatal(err)
			}
			var cfg hallpassSessionCfg
			cfg.setAnyUnix(n.AnyUnix, expiry)
			check := func(what string, obj rules.Object, b int) {
				ev, _, ok := rules.Eval(rs, rules.OpConnect, obj, now)
				want := ok && ev == rules.Allow
				if got := b&(bitAllow|bitDeny) == bitAllow; got != want {
					t.Fatalf("%d: rules %s: %q allowed %v, want %v (Eval %v %v)", i, describe(rs), what, got, want, ev, ok)
				}
			}
			if cands[0].Inet != nil {
				for _, d := range dests {
					ap := netip.MustParseAddrPort(d.addr)
					check(fmt.Sprint(d), rules.Object{Inet: &rules.InetObject{Proto: d.proto, Addr: ap}},
						inetBits(it, ap.Addr(), d.proto, ap.Port(), mono))
				}
				continue
			}
			for _, name := range names {
				check("@"+name, rules.Object{Unix: &rules.UnixObject{Abstract: true, Name: name}}, abstractBits(at, cfg, name, mono))
			}
		}
	}
}
