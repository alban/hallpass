// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

func (g NetGrant) fill(v *hallpassHpGrant) {
	for i, d := range g.Inet {
		v.Inet[i].Addr = d.Addr.Addr().As16()
		v.Inet[i].Port = d.Addr.Port()
		v.Inet[i].Proto = d.Proto
		v.Inet[i].Set = 1
	}
	if g.Abstract != nil {
		v.AbstractSet = 1
		v.AbstractLen = uint32(len(*g.Abstract))
		for i := 0; i < len(*g.Abstract); i++ {
			v.Abstract[i] = int8((*g.Abstract)[i])
		}
	}
}

// netEntries is the number of rules a prefix of the tries holds, its own
// and those of the shorter prefixes containing it.
const netEntries = len(hallpassInetVal{}.E)

// Bits of session_cfg.flags.
const ownListeners = 1

// SyncNet makes the kernel's network rules for the session match these.
// Expired allow rules are dropped.
func (s *Session) SyncNet(net NetRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	expiry := expiryClock()

	inet, err := inetTrie(s.id, net.Inet, expiry)
	if err != nil {
		return err
	}
	abs, err := abstractTrie(s.id, net.Abstract, expiry)
	if err != nil {
		return err
	}
	if err := syncMap(s.l.inet, s.inet, inet, same); err != nil {
		return fmt.Errorf("update inet rules: %w", err)
	}
	s.inet = inet
	if err := syncMap(s.l.abstract, s.abs, abs, same); err != nil {
		return fmt.Errorf("update abstract unix rules: %w", err)
	}
	s.abs = abs

	cfg := s.cfg
	cfg.Flags = 0
	if net.OwnListeners {
		cfg.Flags |= ownListeners
	}
	cfg.setAnyUnix(net.AnyUnix, expiry)
	if cfg != s.cfg {
		if cfg.Mediate == 0 {
			// No entry yet: the default, files.
			cfg.Mediate = mediateFiles
		}
		if err := s.l.cfgs.Update(s.id, cfg, ebpf.UpdateAny); err != nil {
			return err
		}
		s.cfg = cfg
	}
	return nil
}

// setAnyUnix sets the rules for every unix socket of cfg to rs.
func (cfg *hallpassSessionCfg) setAnyUnix(rs []UnixAnyRule, expiry func(time.Time) uint64) {
	cfg.AnyUnixAllow, cfg.AnyUnixAsk, cfg.AnyUnixDeny = 0, 0, 0
	for _, r := range rs {
		switch {
		case r.Deny:
			cfg.AnyUnixDeny = 1
		case r.Ask:
			cfg.AnyUnixAsk = max(cfg.AnyUnixAsk, expiry(r.Expires))
		default:
			cfg.AnyUnixAllow = max(cfg.AnyUnixAllow, expiry(r.Expires))
		}
	}
}

type entryInet struct {
	expiry        uint64
	lo, hi, proto uint16
	depth         uint16
	deny, ask     bool
}

// inetTrie computes the inet_rules entries of rules: one key per prefix,
// with the rules of that prefix and of the shorter ones containing it.
//
// IPv4 prefixes are stored as IPv4-mapped IPv6 ones (::ffff:a.b.c.d), in
// the same trie. An IPv6 prefix does not contain IPv4 addresses (as in
// lite mode, netip.Prefix.Contains): IPv4 keys do not inherit IPv6 rules,
// and a ::ffff:0:0/96 key, with the rules for any address only, keeps
// IPv4 lookups off IPv6 prefixes as short as /96 or less. ::/0 shares its
// key with the rules for any address; the keys below inherit them apart.
func inetTrie(session uint32, rules []InetRule, expiry func(time.Time) uint64) (map[hallpassInetKey]hallpassInetVal, error) {
	root := hallpassInetKey{Prefixlen: 32, Session: session}
	own := map[hallpassInetKey][]entryInet{root: nil}
	pfx := map[hallpassInetKey]netip.Prefix{root: {}}
	v4 := map[hallpassInetKey]bool{}
	var anyAddr, anyV6 []entryInet
	mapped := netip.PrefixFrom(netip.AddrFrom16(netip.IPv4Unspecified().As16()), 96)
	shadow := false
	for _, r := range rules {
		e := entryInet{proto: r.Proto, lo: r.PortLo, hi: r.PortHi}
		if r.Deny {
			e.deny = true
		} else if e.expiry = expiry(r.Expires); e.expiry == 0 {
			continue
		} else {
			e.ask, e.depth = r.Ask, r.Depth
		}
		k := root
		if !r.Prefix.IsValid() {
			anyAddr = mergeInet(anyAddr, e)
		} else {
			bits := r.Prefix.Bits()
			a := r.Prefix.Masked().Addr()
			if a.Is4() {
				bits += 96
			} else if bits <= 96 && r.Prefix.Masked().Contains(mapped.Addr()) {
				shadow = true
			}
			if !a.Is4() && bits >= 96 && mapped.Contains(a) {
				// Addresses are unmapped: no IPv6 address is in there.
				continue
			}
			p := netip.PrefixFrom(netip.AddrFrom16(a.As16()), bits)
			k.Prefixlen += uint32(bits)
			k.Addr = p.Addr().As16()
			if bits == 0 {
				anyV6 = mergeInet(anyV6, e)
			} else {
				pfx[k] = p
				v4[k] = a.Is4()
			}
		}
		own[k] = mergeInet(own[k], e)
	}
	if shadow {
		k := hallpassInetKey{Prefixlen: 32 + 96, Session: session, Addr: mapped.Addr().As16()}
		if _, ok := pfx[k]; !ok {
			pfx[k], v4[k] = mapped, true
		}
	}
	out := map[hallpassInetKey]hallpassInetVal{}
	for k, p := range pfx {
		es := append([]entryInet(nil), own[k]...)
		if k != root {
			for _, e := range anyAddr {
				es = mergeInet(es, e)
			}
			if !v4[k] {
				for _, e := range anyV6 {
					es = mergeInet(es, e)
				}
			}
		}
		for k2, p2 := range pfx {
			if k2 == k || k2 == root || k2.Prefixlen >= k.Prefixlen {
				continue
			}
			if v4[k] == v4[k2] && p2.Contains(p.Addr()) {
				for _, e := range own[k2] {
					es = mergeInet(es, e)
				}
			}
		}
		if len(es) == 0 && k == root {
			continue
		}
		es = flattenInet(es)
		if len(es) > netEntries {
			return nil, fmt.Errorf("strict mode: more than %d network rules match %s", netEntries, p)
		}
		var v hallpassInetVal
		for i, e := range es {
			v.E[i].Expiry, v.E[i].PortLo, v.E[i].PortHi, v.E[i].Proto = e.expiry, e.lo, e.hi, e.proto
			v.E[i].Depth = e.depth
			if e.deny {
				v.E[i].Deny = 1
			}
			if e.ask {
				v.E[i].Ask = 1
			}
		}
		out[k] = v
	}
	return out, nil
}

// mergeInet adds e to es, merging it with a rule on the same ports and
// protocol, of the same kind, that is as deep and lasts as long, or that
// e is.
func mergeInet(es []entryInet, e entryInet) []entryInet {
	for i, o := range es {
		if o.lo != e.lo || o.hi != e.hi || o.proto != e.proto || o.deny != e.deny || o.ask != e.ask {
			continue
		}
		switch {
		case e.deny || o.depth >= e.depth && o.expiry >= e.expiry:
			return es
		case e.depth >= o.depth && e.expiry >= o.expiry:
			es[i] = e
			return es
		}
	}
	return append(es, e)
}

// flattenInet merges the allows on the same ports and protocol when no
// ask needs their depths: one that lasts the longest is enough.
func flattenInet(es []entryInet) []entryInet {
	for _, e := range es {
		if e.ask {
			return es
		}
	}
	var out []entryInet
next:
	for _, e := range es {
		for i, o := range out {
			if o.lo == e.lo && o.hi == e.hi && o.proto == e.proto && o.deny == e.deny {
				out[i].expiry, out[i].depth = max(o.expiry, e.expiry), max(o.depth, e.depth)
				continue next
			}
		}
		out = append(out, e)
	}
	return out
}

type entryAbs struct {
	expiry uint64
	deny   bool
	ask    bool
	exact  bool
	len    uint8
}

// abstractTrie is inetTrie for abstract unix names. Exact rules only apply
// to their own key.
func abstractTrie(session uint32, rules []AbstractRule, expiry func(time.Time) uint64) (map[hallpassAbstractKey]hallpassAbstractVal, error) {
	maxName := len(hallpassAbstractKey{}.Name) - 1
	own := map[string][]entryAbs{}
	for _, r := range rules {
		if len(r.Name) > maxName {
			continue // no such name
		}
		e := entryAbs{exact: !r.Prefix, len: uint8(len(r.Name))}
		if r.Deny {
			e.deny = true
		} else if e.expiry = expiry(r.Expires); e.expiry == 0 {
			continue
		} else {
			e.ask = r.Ask
		}
		own[r.Name] = mergeAbs(own[r.Name], e)
	}
	out := map[hallpassAbstractKey]hallpassAbstractVal{}
	for name, es := range own {
		es = append([]entryAbs(nil), es...)
		for n2, es2 := range own {
			if len(n2) >= len(name) || !strings.HasPrefix(name, n2) {
				continue
			}
			for _, e := range es2 {
				if !e.exact {
					es = mergeAbs(es, e)
				}
			}
		}
		if len(es) > netEntries {
			return nil, fmt.Errorf("strict mode: more than %d network rules match unix @%s", netEntries, name)
		}
		k := hallpassAbstractKey{Prefixlen: 32 + 8*uint32(len(name)), Session: session}
		copyName(k.Name[:], name)
		var v hallpassAbstractVal
		for i, e := range es {
			v.E[i].Expiry, v.E[i].Len = e.expiry, e.len
			if e.deny {
				v.E[i].Deny = 1
			}
			if e.exact {
				v.E[i].Exact = 1
			}
			if e.ask {
				v.E[i].Ask = 1
			}
		}
		out[k] = v
	}
	return out, nil
}

func mergeAbs(es []entryAbs, e entryAbs) []entryAbs {
	for i, o := range es {
		if o.deny == e.deny && o.ask == e.ask && o.exact == e.exact && o.len == e.len {
			es[i].expiry = max(o.expiry, e.expiry)
			return es
		}
	}
	return append(es, e)
}
