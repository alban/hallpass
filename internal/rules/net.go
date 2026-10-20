// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

// Protocol numbers with a name in prompts and rule specs.
var protoNames = map[uint16]string{
	1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6", 132: "sctp", 136: "udplite", 262: "mptcp",
}

// ProtoName names IP protocol p: "tcp", "udp", or "ip/<n>".
func ProtoName(p uint16) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return "ip/" + strconv.Itoa(int(p))
}

func protoByName(s string) (uint16, bool) {
	for p, n := range protoNames {
		if n == s {
			return p, true
		}
	}
	return 0, false
}

// String shows o the way prompts do: "tcp 140.82.112.21:443",
// "unix /run/docker.sock", "unix @name".
func (o *InetObject) String() string {
	return ProtoName(o.Proto) + " " + o.Addr.String()
}

func (o *UnixObject) String() string {
	if o.Abstract {
		return "unix @" + o.Name
	}
	return "unix " + o.Path
}

// NetString shows a network match in the syntax ParseNet reads, or ""
// if m is not one.
func (m ObjectMatch) NetString() string {
	switch {
	case m.AnyNet:
		return "all"
	case m.OwnListener:
		return "own-listeners"
	case m.Unix != nil:
		u := m.Unix
		if u.Abstract {
			s := "unix:@" + u.Name
			if u.Prefix {
				s += "*"
			}
			return s
		}
		if u.Prefix {
			return "unix:" + strings.TrimSuffix(u.Path, "/") + "/**"
		}
		return "unix:" + u.Path
	case m.Inet != nil:
		i := m.Inet
		s := ""
		if i.Proto != 0 {
			s = ProtoName(i.Proto) + ":"
		}
		switch {
		case !i.Prefix.IsValid():
			s += "*"
		case i.Prefix.Addr().Is6():
			s += "[" + i.Prefix.Addr().String() + "]"
			if i.Prefix.Bits() != 128 {
				s += "/" + strconv.Itoa(i.Prefix.Bits())
			}
		default:
			s += i.Prefix.Addr().String()
			if i.Prefix.Bits() != 32 {
				s += "/" + strconv.Itoa(i.Prefix.Bits())
			}
		}
		if i.PortLo != 0 || i.PortHi != 0 {
			s += ":" + strconv.Itoa(int(i.PortLo))
			if i.PortHi != i.PortLo {
				s += "-" + strconv.Itoa(int(i.PortHi))
			}
		}
		return s
	}
	return ""
}

// ParseNet reads a network match:
//
//	all                     every destination, unix sockets included
//	[PROTO:]ADDR[:PORTS]    PROTO: tcp, udp...; ADDR: 1.2.3.4, 10.0.0.0/8,
//	                        [2001:db8::1], [2001:db8::]/32 or * (any);
//	                        PORTS: 443 or 8000-8999
//	unix:/path              a unix socket file; unix:/dir/** below /dir
//	unix:@name              an abstract name; unix:@prefix* a prefix
func ParseNet(s string) (ObjectMatch, error) {
	if s == "all" {
		return ObjectMatch{AnyNet: true}, nil
	}
	if rest, ok := strings.CutPrefix(s, "unix:"); ok {
		return parseUnix(rest)
	}
	var m InetMatch
	if p, rest, ok := strings.Cut(s, ":"); ok {
		if n, ok := protoByName(p); ok {
			m.Proto, s = n, rest
		}
	}
	addr, ports := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return ObjectMatch{}, fmt.Errorf("%q: missing ]", s)
		}
		addr, ports = s[1:end], s[end+1:]
		if bits, rest, ok := strings.Cut(ports, ":"); ok && strings.HasPrefix(bits, "/") {
			addr, ports = addr+bits, ":"+rest
		} else if strings.HasPrefix(ports, "/") {
			addr, ports = addr+ports, ""
		}
		if ports != "" && !strings.HasPrefix(ports, ":") {
			return ObjectMatch{}, fmt.Errorf("%q: want :PORT after ]", s)
		}
		ports = strings.TrimPrefix(ports, ":")
	case strings.Count(s, ":") > 1:
		// A bare IPv6 address or prefix: no port.
	default:
		addr, ports, _ = strings.Cut(s, ":")
	}
	if addr != "*" {
		p, err := parsePrefix(addr)
		if err != nil {
			return ObjectMatch{}, err
		}
		m.Prefix = p
	}
	if ports != "" {
		lo, hi, err := parsePorts(ports)
		if err != nil {
			return ObjectMatch{}, fmt.Errorf("%q: %w", s, err)
		}
		m.PortLo, m.PortHi = lo, hi
	}
	return ObjectMatch{Inet: &m}, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parsePorts(s string) (lo, hi uint16, err error) {
	l, h, isRange := strings.Cut(s, "-")
	a, err := strconv.ParseUint(l, 10, 16)
	if err != nil || a == 0 {
		return 0, 0, fmt.Errorf("bad port %q", l)
	}
	b := a
	if isRange {
		if b, err = strconv.ParseUint(h, 10, 16); err != nil || b < a {
			return 0, 0, fmt.Errorf("bad port range %q", s)
		}
	}
	return uint16(a), uint16(b), nil
}

func parseUnix(s string) (ObjectMatch, error) {
	if name, ok := strings.CutPrefix(s, "@"); ok {
		u := &UnixMatch{Abstract: true, Name: name}
		if n, ok := strings.CutSuffix(name, "*"); ok {
			u.Name, u.Prefix = n, true
		}
		if u.Name == "" && !u.Prefix {
			return ObjectMatch{}, errors.New("unix:@: empty abstract name")
		}
		return ObjectMatch{Unix: u}, nil
	}
	u := &UnixMatch{Path: s}
	if p, ok := strings.CutSuffix(s, "/**"); ok {
		u.Path, u.Prefix = p, true
		if u.Path == "" {
			u.Path = "/"
		}
	}
	if !filepath.IsAbs(u.Path) {
		return ObjectMatch{}, fmt.Errorf("unix:%s: want an absolute path or @name", s)
	}
	u.Path = filepath.Clean(u.Path)
	return ObjectMatch{Unix: u}, nil
}

// CoversNet reports whether network match m selects every destination
// network match o selects. Only every destination (AnyNet) covers every
// destination, and only it or own listeners cover own listeners.
func (m ObjectMatch) CoversNet(o ObjectMatch) bool {
	switch {
	case !m.IsNet() || !o.IsNet():
		return false
	case m.AnyNet:
		return true
	case m.OwnListener && o.OwnListener:
		return true
	case o.AnyNet || m.OwnListener || o.OwnListener:
		return false
	case m.Inet != nil && o.Inet != nil:
		return m.Inet.covers(o.Inet)
	case m.Unix != nil && o.Unix != nil:
		return m.Unix.covers(o.Unix)
	}
	return false
}

// OverlapsNet reports whether network matches m and o may select a
// destination in common. Own listeners (any loopback or unix address)
// overlap every network match.
func (m ObjectMatch) OverlapsNet(o ObjectMatch) bool {
	switch {
	case !m.IsNet() || !o.IsNet():
		return false
	case m.AnyNet || o.AnyNet || m.OwnListener || o.OwnListener:
		return true
	case m.Inet != nil && o.Inet != nil:
		return m.Inet.overlaps(o.Inet)
	case m.Unix != nil && o.Unix != nil:
		return m.Unix.covers(o.Unix) || o.Unix.covers(m.Unix)
	}
	return false
}

func (m *InetMatch) covers(o *InetMatch) bool {
	if m.Proto != 0 && m.Proto != o.Proto {
		return false
	}
	if m.PortLo != 0 || m.PortHi != 0 {
		if (o.PortLo == 0 && o.PortHi == 0) || o.PortLo < m.PortLo || o.PortHi > m.PortHi {
			return false
		}
	}
	if m.Prefix.IsValid() {
		return o.Prefix.IsValid() && m.Prefix.Bits() <= o.Prefix.Bits() && m.Prefix.Contains(o.Prefix.Addr())
	}
	return true
}

func (m *InetMatch) overlaps(o *InetMatch) bool {
	if m.Proto != 0 && o.Proto != 0 && m.Proto != o.Proto {
		return false
	}
	if (m.PortLo != 0 || m.PortHi != 0) && (o.PortLo != 0 || o.PortHi != 0) && (m.PortHi < o.PortLo || o.PortHi < m.PortLo) {
		return false
	}
	return !m.Prefix.IsValid() || !o.Prefix.IsValid() || m.Prefix.Overlaps(o.Prefix)
}

func (m *UnixMatch) covers(o *UnixMatch) bool {
	if m.Abstract != o.Abstract {
		return false
	}
	if m.Abstract {
		if m.Prefix {
			return strings.HasPrefix(o.Name, m.Name)
		}
		return !o.Prefix && o.Name == m.Name
	}
	if m.Prefix {
		return Under(o.Path, m.Path)
	}
	return !o.Prefix && o.Path == m.Path
}

// ExactNet returns the match for exactly o's destination: one address and
// port, any protocol, or one unix path or abstract name. Answers use it:
// the protocol is left out because glibc's getaddrinfo connects a UDP
// socket to each address (to sort them, sending nothing) before the
// program connects with TCP, and both should be one question.
func ExactNet(o Object) ObjectMatch {
	if o.Unix != nil {
		return ObjectMatch{Unix: &UnixMatch{Path: o.Unix.Path, Abstract: o.Unix.Abstract, Name: o.Unix.Name}}
	}
	a := o.Inet.Addr.Addr().Unmap()
	m := &InetMatch{Prefix: netip.PrefixFrom(a, a.BitLen())}
	if p := o.Inet.Addr.Port(); p != 0 {
		m.PortLo, m.PortHi = p, p
	}
	return ObjectMatch{Inet: m}
}
