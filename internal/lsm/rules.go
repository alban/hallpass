// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// grant is one GrantOnce: its paths keep their rule nodes, so their cookies
// stay valid, until the grant is used up.
type grant struct {
	pidfd int
	seq   uint64
	paths []string
}

// Sync makes the kernel's rules for the session match these, translating
// paths with the current mounts. Expired rules are dropped.
func (s *Session) Sync(rules []Rule, procs []ProcRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	s.lastRules, s.lastProcs = rules, procs
	s.pruneOnce()
	_, err := s.sync()
	return err
}

// mountID is the id of the mount p is on, in the session's root.
func (s *Session) mountID(p string) uint64 {
	if s.inRoot == "" {
		return mountID(p)
	}
	return mountIDIn(s.inRoot, p)
}

// sync pushes lastRules and lastProcs, with nodes for the paths of the
// grants, and returns the mounts it used. s.mu must be held.
func (s *Session) sync() ([]mount, error) {
	mounts, err := readMounts(s.mountinfo)
	if err != nil {
		return nil, err
	}
	expiry := expiryClock()

	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	nodes := s.ruleNodes(mounts, expiry)
	if err := syncMap(s.l.rules, s.nodes, nodes, s.ruleKey); err != nil {
		return nil, fmt.Errorf("update rules: %w", err)
	}
	s.nodes = nodes

	procs := s.procRules(expiry)
	if err := syncMap(s.l.proc, s.procs, procs, same); err != nil {
		return nil, err
	}
	s.procs = procs
	return mounts, nil
}

// ruleNodes returns the rule nodes of lastRules, and those of the paths of
// the grants. s.l.mu must be held.
func (s *Session) ruleNodes(mounts []mount, expiry func(time.Time) uint64) map[nodeKey]hallpassRuleVal {
	nodes := map[nodeKey]hallpassRuleVal{}
	levels := map[nodeKey]*nodeLevels{}
	for _, r := range s.lastRules {
		exp := expiry(r.Expires)
		if exp == 0 {
			continue
		}
		for _, lc := range locate(mounts, r.Path, r.Tree, s.mountID(r.Path)) {
			if k, ok := s.l.node(nodes, lc); ok {
				lv := levels[k]
				if lv == nil {
					lv = newNodeLevels()
					levels[k] = lv
				}
				r.addTo(lv, exp)
			}
		}
	}
	for k, lv := range levels {
		v := nodes[k]
		lv.fill(&v)
		nodes[k] = v
	}
	// The grants' nodes: they allow nothing by themselves.
	for _, g := range s.once {
		for _, p := range g.paths {
			for _, lc := range locate(mounts, p, false, s.mountID(p)) {
				s.l.node(nodes, lc)
			}
		}
	}
	return nodes
}

// level is the rules of one node for its tree, or for itself only (exact),
// for files, for unix sockets or for programs: the expiries of the allows
// and the asks, and the depth (length of the host path) of the deepest of
// each, -1 for none.
type level struct {
	allow, ask   uint64
	allowD, askD int
	deny         bool
}

// nodeLevels are the levels of a node, indexed by levelOf.
type nodeLevels [6]level

func newNodeLevels() *nodeLevels {
	var lv nodeLevels
	for i := range lv {
		lv[i].allowD, lv[i].askD = -1, -1
	}
	return &lv
}

func (r Rule) levelOf() int {
	i := 0
	switch {
	case r.Net:
		i = 2
	case r.Exec:
		i = 4
	}
	if !r.Tree {
		i++
	}
	return i
}

// addTo adds r, allowing or asking until exp, to the levels of its node.
func (r Rule) addTo(lv *nodeLevels, exp uint64) {
	l := &lv[r.levelOf()]
	d := len(r.Path)
	switch {
	case r.Deny:
		l.deny = true
	case r.Ask:
		l.ask, l.askD = max(l.ask, exp), max(l.askD, d)
	default:
		l.allow, l.allowD = max(l.allow, exp), max(l.allowD, d)
	}
}

// fill sets the rules of lv in v. The kernel applies, at each node, the
// tree allow, the tree ask, then for the target the exact allow and the
// exact ask: an ask wins over an allow of the same node. Rules of
// different depths only meet at one node through different mounts; then,
// as in rules.Eval, the deepest decides (an ask on a tie), and the rules
// it overrides are dropped. Their expiry is not taken into account.
// Programs have no asks.
func (lv *nodeLevels) fill(v *hallpassRuleVal) {
	tree, exact := lv[0], lv[1]
	resolve(&tree, &exact)
	v.AllowTree, v.AskTree, v.AllowExact, v.AskExact = tree.allow, tree.ask, exact.allow, exact.ask
	v.DenyTree, v.DenyExact = b2u8(tree.deny), b2u8(exact.deny)
	tree, exact = lv[2], lv[3]
	resolve(&tree, &exact)
	v.NetAllowTree, v.NetAskTree, v.NetAllowExact, v.NetAskExact = tree.allow, tree.ask, exact.allow, exact.ask
	v.NetDenyTree, v.NetDenyExact = b2u8(tree.deny), b2u8(exact.deny)
	tree, exact = lv[4], lv[5]
	v.ExecAllowTree, v.ExecAllowExact = tree.allow, exact.allow
	v.ExecDenyTree, v.ExecDenyExact = b2u8(tree.deny), b2u8(exact.deny)
}

// resolve drops the rules of a node that a deeper one of the same node
// overrides, given the kernel's order (see fill).
func resolve(tree, exact *level) {
	if tree.askD < tree.allowD {
		tree.ask = 0
	}
	if exact.askD < max(tree.allowD, exact.allowD) {
		exact.ask = 0
	}
	if exact.allowD <= max(tree.askD, exact.askD) {
		exact.allow = 0
	}
}

func b2u8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// procRules returns the entries of lastProcs.
func (s *Session) procRules(expiry func(time.Time) uint64) map[hallpassProcKey]hallpassProcVal {
	procs := map[hallpassProcKey]hallpassProcVal{}
	for _, r := range s.lastProcs {
		exp := expiry(r.Expires)
		if exp == 0 && !r.Deny {
			continue
		}
		k := s.procKey(r.Name, r.Comm)
		v := procs[k]
		switch {
		case r.Deny:
			v.Deny = 1
		case r.Ask:
			v.Ask = max(v.Ask, exp)
		default:
			v.Allow = max(v.Allow, exp)
		}
		procs[k] = v
	}
	return procs
}

// syncMap makes the entries of m for the keys of had those of want: it
// updates the entries that changed and deletes those gone from want. key
// turns a key of had and want into one of m.
func syncMap[K comparable, V comparable, MK any](m *ebpf.Map, had, want map[K]V, key func(K) MK) error {
	var errs []error
	for k, v := range want {
		if old, ok := had[k]; ok && old == v {
			continue
		}
		if err := m.Update(key(k), v, ebpf.UpdateAny); err != nil {
			errs = append(errs, err)
		}
	}
	for k := range had {
		if _, ok := want[k]; ok {
			continue
		}
		if err := m.Delete(key(k)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// same is the key of syncMap for maps keyed as in the kernel.
func same[K any](k K) K { return k }

// expiryClock returns a function converting expiry times to the clock of
// the programs (monotonic): forever for the zero time, 0 once past.
func expiryClock() func(time.Time) uint64 {
	now := time.Now()
	mono := monotonic()
	return func(t time.Time) uint64 {
		if t.IsZero() {
			return forever
		}
		if !t.After(now) {
			return 0
		}
		return mono + uint64(t.Sub(now))
	}
}

func (s *Session) procKey(name, comm string) hallpassProcKey {
	var k hallpassProcKey
	copyName(k.Name[:], name)
	copyName(k.Comm[:], comm)
	k.Session = s.id
	return k
}

// GrantOnce lets thread tid, a member blocked in a syscall that seccomp
// handed to the supervisor, write paths (exactly), and the /proc file of
// proc when its Name is set, and reach the network destinations of net,
// during that syscall only: the kernel removes
// the grant when the syscall returns, even if it is restarted, and no other
// thread can use it. It must be called before the syscall is continued.
// Unix sockets bound to a path are granted with paths.
func (s *Session) GrantOnce(tid int, paths []string, proc ProcRule, net NetGrant) error {
	if len(net.Inet) > len(hallpassHpGrant{}.Inet) {
		return fmt.Errorf("allow once: too many addresses (%d)", len(net.Inet))
	}
	if net.Abstract != nil && len(*net.Abstract) >= len(hallpassHpGrant{}.Abstract) {
		return fmt.Errorf("allow once: abstract unix name too long")
	}
	fd, err := unix.PidfdOpen(tid, unix.PIDFD_THREAD)
	if err != nil {
		return fmt.Errorf("pidfd_open %d: %w", tid, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		unix.Close(fd)
		return errors.New("session closed")
	}
	s.pruneOnce()
	s.seq++
	g := &grant{pidfd: fd, seq: s.seq, paths: paths}
	s.once = append(s.once, g)
	mounts, err := s.sync()
	if err != nil {
		return err
	}
	v := hallpassHpGrant{Seq: g.seq}
	if err := s.grantNodes(&v, mounts, paths); err != nil {
		return err
	}
	if proc.Name != "" {
		v.Proc = s.procKey(proc.Name, proc.Comm)
	}
	net.fill(&v)
	return s.l.grants.Update(uint32(fd), v, ebpf.UpdateAny)
}

// grantNodes puts the cookies of the nodes of paths in v.
func (s *Session) grantNodes(v *hallpassHpGrant, mounts []mount, paths []string) error {
	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	n := 0
	for _, p := range paths {
		for _, lc := range locate(mounts, p, false, s.mountID(p)) {
			c, ok := s.l.cookie(lc)
			if !ok {
				continue
			}
			if n == len(v.Nodes) {
				return fmt.Errorf("allow once: too many paths (%d)", len(paths))
			}
			v.Nodes[n] = c
			n++
		}
	}
	return nil
}

// pruneOnce forgets the grants the kernel has removed: their syscall
// returned, or their thread exited. s.mu must be held.
func (s *Session) pruneOnce() {
	once := s.once[:0]
	for _, g := range s.once {
		var v hallpassHpGrant
		if err := s.l.grants.Lookup(uint32(g.pidfd), &v); err == nil && v.Seq == g.seq {
			once = append(once, g)
			continue
		}
		unix.Close(g.pidfd)
	}
	clear(s.once[len(once):])
	s.once = once
}

// cookie returns the cookie of the node of lc, if it has one. l.mu must be
// held.
func (l *LSM) cookie(lc loc) (uint64, bool) {
	parent := rootCookie | uint64(lc.dev)
	c := uint64(0)
	for _, name := range strings.Split(lc.path, "/") {
		if name == "" {
			continue
		}
		if c = l.cookies[nodeKey{parent, name}]; c == 0 {
			return 0, false
		}
		parent = c
	}
	return c, c != 0
}

// node adds the nodes leading to lc to nodes and returns the key of its last
// one. Cookies are stable for the life of the LSM. l.mu must be held.
func (l *LSM) node(nodes map[nodeKey]hallpassRuleVal, lc loc) (nodeKey, bool) {
	parent := rootCookie | uint64(lc.dev)
	var comps []string
	for _, c := range strings.Split(lc.path, "/") {
		if c == "" {
			continue
		}
		if len(c) >= nameLen {
			return nodeKey{}, false // cannot exist
		}
		comps = append(comps, c)
	}
	if len(comps) == 0 {
		return nodeKey{parent, ""}, true
	}
	var k nodeKey
	for _, c := range comps {
		k = nodeKey{parent, c}
		v := nodes[k]
		if v.Cookie == 0 {
			if l.cookies[k] == 0 {
				l.cookies[k] = l.next
				l.next++
			}
			v.Cookie = l.cookies[k]
			nodes[k] = v
		}
		parent = v.Cookie
	}
	return k, true
}

// ruleKey is the key of node k of the session in the rules map.
func (s *Session) ruleKey(k nodeKey) hallpassRuleKey { return ruleKey(s.id, k) }

func ruleKey(session uint32, k nodeKey) hallpassRuleKey {
	var rk hallpassRuleKey
	rk.Parent = k.parent
	rk.Session = session
	copyName(rk.Name[:], k.name)
	return rk
}

// copyName copies s into a NUL-padded C string, truncating as the kernel's
// bpf_probe_read_kernel_str and comm do.
func copyName(dst []int8, s string) {
	for i := 0; i < len(s) && i < len(dst)-1; i++ {
		dst[i] = int8(s[i])
	}
}

// monotonic is bpf_ktime_get_ns's clock.
func monotonic() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}
