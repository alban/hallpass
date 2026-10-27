// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"errors"
	"time"

	"github.com/cilium/ebpf"
)

func (g NetGrant) fill(v *hallpassHpGrant) {
	for i, d := range g.Inet[:min(len(g.Inet), len(v.Inet))] {
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

// Bits of session_cfg.flags.
const ownListeners = 1

// SyncUnix makes the kernel's rules for the session's unix sockets bound
// to a path match these. Expired allow rules are dropped.
func (s *Session) SyncUnix(u UnixRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session closed")
	}
	cfg := s.cfg
	cfg.Flags = 0
	if u.OwnListeners {
		cfg.Flags |= ownListeners
	}
	cfg.setAnyUnix(u.AnyUnix, expiryClock())
	if cfg == s.cfg {
		return nil
	}
	if cfg.Mediate == 0 {
		// No entry yet: the default, files.
		cfg.Mediate = mediateFiles
	}
	if err := s.l.cfgs.Update(s.id, cfg, ebpf.UpdateAny); err != nil {
		return err
	}
	s.cfg = cfg
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
