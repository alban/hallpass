// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsnames

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// maxChain bounds the CNAME records followed from a question's name.
const maxChain = 16

// AnswerMsg records the A and AAAA records of DNS response msg that
// answer its questions, through CNAME chains, as Answer does: each name
// of the chain, from the question's to the last alias, gets the
// addresses, for the smallest TTL along the chain. Anything that is not
// a successful response is ignored. The caller relayed msg to the session
// from a server it may use.
func (n *Names) AnswerMsg(msg []byte) {
	for _, a := range Answers(msg) {
		// The question's name last: most recent first.
		for i := len(a.Names) - 1; i >= 0; i-- {
			n.Answer(a.Names[i], a.Addrs, a.TTL)
		}
	}
}

// Answered is what a DNS response says of one question: its name and the
// aliases leading to the addresses (Names[0] the question's), and the
// smallest TTL along the way.
type Answered struct {
	Names []string
	Addrs []netip.Addr
	TTL   time.Duration
}

// Answers returns, for each A, AAAA or ANY question of DNS response msg
// with addresses, the names and addresses its answer section gives. A
// query, an error response or a malformed message gives none.
func Answers(msg []byte) []Answered {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return nil
	}
	type rec struct {
		target string // CNAME
		addr   netip.Addr
		ttl    uint32
	}
	byName := map[string][]rec{}
	for {
		rh, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil
		}
		owner := normalize(rh.Name.String())
		switch {
		case rh.Class != dnsmessage.ClassINET:
			err = p.SkipAnswer()
		case rh.Type == dnsmessage.TypeA:
			var r dnsmessage.AResource
			if r, err = p.AResource(); err == nil {
				byName[owner] = append(byName[owner], rec{addr: netip.AddrFrom4(r.A), ttl: rh.TTL})
			}
		case rh.Type == dnsmessage.TypeAAAA:
			var r dnsmessage.AAAAResource
			if r, err = p.AAAAResource(); err == nil {
				byName[owner] = append(byName[owner], rec{addr: netip.AddrFrom16(r.AAAA).Unmap(), ttl: rh.TTL})
			}
		case rh.Type == dnsmessage.TypeCNAME:
			var r dnsmessage.CNAMEResource
			if r, err = p.CNAMEResource(); err == nil {
				byName[owner] = append(byName[owner], rec{target: normalize(r.CNAME.String()), ttl: rh.TTL})
			}
		default:
			err = p.SkipAnswer()
		}
		if err != nil {
			return nil
		}
	}
	var out []Answered
	var seen []string
	for _, q := range qs {
		if q.Class != dnsmessage.ClassINET || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && q.Type != dnsmessage.TypeALL) {
			continue
		}
		name := normalize(q.Name.String())
		if name == "" || slices.Contains(seen, name) {
			continue
		}
		seen = append(seen, name)
		a := Answered{TTL: -1}
		for cur, i := name, 0; cur != "" && i <= maxChain && !slices.Contains(a.Names, cur); i++ {
			a.Names = append(a.Names, cur)
			next := ""
			for _, r := range byName[cur] {
				ttl := time.Duration(r.ttl) * time.Second
				switch {
				case r.addr.IsValid():
					if !slices.Contains(a.Addrs, r.addr) {
						a.Addrs = append(a.Addrs, r.addr)
					}
				case next == "":
					next = r.target
				default:
					continue
				}
				if a.TTL < 0 || ttl < a.TTL {
					a.TTL = ttl
				}
			}
			cur = next
		}
		if len(a.Addrs) > 0 {
			out = append(out, a)
		}
	}
	return out
}

// validName reports whether s looks like a host name: what a prompt shows
// must not carry anything else (the session chose it).
func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r == '*')
	})
}
