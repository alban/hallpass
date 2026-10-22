// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsnames

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"strings"
)

// ResolveSocket is systemd-resolved's varlink socket: glibc's nss-resolve
// (Fedora, Arch) resolves names through it, never through port 53.
const ResolveSocket = "/run/systemd/resolve/io.systemd.Resolve"

// Varlink follows one connection to systemd-resolved's varlink service:
// the calls the session sends (Call) and the replies it gets (Reply), in
// order, each a JSON message without its NUL terminator. The addresses of
// ResolveHostname replies are recorded for the names asked (Answer).
//
// Varlink answers calls in order; a call with "oneway" has no reply, one
// with "more" has replies until one without "continues". After a call
// with "upgrade" the connection carries another protocol: Varlink stops
// following it (Done).
type Varlink struct {
	n       *Names
	pending []string // names of the calls awaiting replies; "" not ResolveHostname
	done    bool
}

// maxPending bounds the calls followed: a session pipelining more calls
// than this is no longer followed.
const maxPending = 256

// NewVarlink returns a follower of a new connection, recording into n.
func NewVarlink(n *Names) *Varlink { return &Varlink{n: n} }

// Done reports whether v stopped following the connection.
func (v *Varlink) Done() bool { return v.done }

// Stop stops following the connection (a message too large to parse).
func (v *Varlink) Stop() { v.done = true }

// Call follows a message the session sent.
func (v *Varlink) Call(msg []byte) {
	if v.done {
		return
	}
	var c struct {
		Method     string `json:"method"`
		Parameters struct {
			Name string `json:"name"`
		} `json:"parameters"`
		Oneway  bool `json:"oneway"`
		Upgrade bool `json:"upgrade"`
	}
	if !plainJSON(msg) || json.Unmarshal(msg, &c) != nil || c.Upgrade || len(v.pending) >= maxPending {
		v.done = true
		return
	}
	if c.Oneway {
		return
	}
	name := ""
	if c.Method == "io.systemd.Resolve.ResolveHostname" {
		name = normalize(c.Parameters.Name)
	}
	v.pending = append(v.pending, name)
}

// Reply follows a message the session received.
func (v *Varlink) Reply(msg []byte) {
	if v.done {
		return
	}
	if len(v.pending) == 0 {
		v.done = true
		return
	}
	var r struct {
		Parameters struct {
			Addresses []struct {
				Family int `json:"family"`
				// An array of numbers: not []byte, which JSON reads
				// as base64.
				Address []int `json:"address"`
			} `json:"addresses"`
		} `json:"parameters"`
		Continues bool   `json:"continues"`
		Error     string `json:"error"`
	}
	if !plainJSON(msg) || json.Unmarshal(msg, &r) != nil {
		v.done = true
		return
	}
	name := v.pending[0]
	if !r.Continues {
		v.pending = v.pending[1:]
	}
	if name == "" || r.Error != "" {
		return
	}
	var addrs []netip.Addr
	for _, a := range r.Parameters.Addresses {
		const afInet, afInet6 = 2, 10
		b := make([]byte, 0, 16)
		for _, x := range a.Address {
			if x < 0 || x > 255 {
				b = nil
				break
			}
			b = append(b, byte(x))
		}
		switch {
		case a.Family == afInet && len(b) == 4:
			addrs = append(addrs, netip.AddrFrom4([4]byte(b)))
		case a.Family == afInet6 && len(b) == 16:
			addrs = append(addrs, netip.AddrFrom16([16]byte(b)).Unmap())
		}
	}
	// resolved gives no TTL: Answer keeps the names for Floor.
	v.n.Answer(name, addrs, 0)
}

// plainJSON reports whether msg is JSON whose objects have no key twice,
// even with another case: Go's decoder takes the last of duplicate keys,
// and matches keys whatever their case, where resolved may read them
// otherwise (a call it takes as oneway while Varlink waits for its reply
// would shift every later reply onto the wrong name).
func plainJSON(msg []byte) bool {
	d := json.NewDecoder(bytes.NewReader(msg))
	d.UseNumber()
	var walk func() bool
	walk = func() bool {
		t, err := d.Token()
		if err != nil {
			return false
		}
		switch t {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return false
				}
				key, ok := k.(string)
				if !ok || seen[strings.ToLower(key)] {
					return false
				}
				seen[strings.ToLower(key)] = true
				if !walk() {
					return false
				}
			}
			_, err := d.Token()
			return err == nil
		case json.Delim('['):
			for d.More() {
				if !walk() {
					return false
				}
			}
			_, err := d.Token()
			return err == nil
		}
		return true
	}
	if !walk() {
		return false
	}
	_, err := d.Token()
	return errors.Is(err, io.EOF)
}
