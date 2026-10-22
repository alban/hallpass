// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lsm

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"

	"golang.org/x/sys/unix"
)

var opNames = [...]string{1: "open", "create", "mkdir", "rmdir", "unlink", "symlink", "link", "rename", "truncate", "connect", "send", "exec"}

// Events calls fn for each decision on the session's members reported by
// the programs, until the session or the LSM is closed.
func (s *Session) Events(fn func(Event)) {
	s.mu.Lock()
	s.fn = fn
	s.mu.Unlock()
	s.l.mu.Lock()
	read := !s.l.reading
	s.l.reading = true
	s.l.mu.Unlock()
	if read {
		go s.l.read()
	}
	<-s.done
}

// read dispatches the events of the ring buffer to their sessions.
func (l *LSM) read() {
	for {
		rec, err := l.rd.Read()
		if err != nil {
			return
		}
		var ev hallpassEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.NativeEndian, &ev); err != nil {
			continue
		}
		l.mu.Lock()
		s := l.sessions[ev.Session]
		l.mu.Unlock()
		if s == nil {
			continue
		}
		s.mu.Lock()
		fn := s.fn
		s.mu.Unlock()
		if fn != nil {
			fn(toEvent(&ev))
		}
	}
}

// toEvent decodes ev.
func toEvent(ev *hallpassEvent) Event {
	e := Event{PID: ev.Pid, Comm: cstr(ev.Comm[:]), Path: cstr(ev.Path[:]), Allowed: ev.Ret == 0}
	if int(ev.Op) < len(opNames) {
		e.Op = opNames[ev.Op]
	}
	switch ev.Family {
	case unix.AF_INET6:
		e.Path = ""
		e.Inet = &InetDest{Addr: netip.AddrPortFrom(netip.AddrFrom16(ev.Addr).Unmap(), ev.Port), Proto: ev.Proto}
		return e
	case unix.AF_UNIX:
		e.Unix = &UnixDest{}
		if ev.NameLen > 0 {
			b := make([]byte, min(int(ev.NameLen), len(ev.Path)))
			for i := range b {
				b[i] = byte(ev.Path[i])
			}
			e.Unix.Abstract, e.Unix.Name = true, string(b)
		} else {
			// Only the name of the socket file is known.
			e.Unix.Path = "…/" + cstr(ev.Name[:])
		}
		e.Path = ""
		return e
	}
	if n := cstr(ev.Name[:]); n != "" {
		if e.Path == "" {
			// Source of a link: the hook gets no path for its directory.
			e.Path = "…"
		}
		e.Path = strings.TrimSuffix(e.Path, "/") + "/" + n
	}
	return e
}

func cstr(b []int8) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}
