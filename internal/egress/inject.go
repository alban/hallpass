// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// Credential is a secret the proxy puts on the wire in place of its
// placeholder, in requests to its hosts only. The sandbox holds the
// placeholder (in its environment): a placeholder that leaks is useless
// outside the session.
type Credential struct {
	Name        string // the profile, for messages
	Hosts       []Host
	Placeholder string // "" when the sandbox has the value itself (pass)
	Value       string
}

func (c *Credential) forHost(host string) bool {
	for _, h := range c.Hosts {
		if h.matches(host) {
			return true
		}
	}
	return false
}

// leaked returns the credential whose placeholder or value is in the
// headers of a request to host, not one of its hosts. A tripwire, not
// the protection (the placeholder and the connect and http rules are):
// it sees only the literal strings, in headers and Basic authorization,
// of the requests through the proxy; an encoding, a body (not read:
// cost), another host or DNS go around it. The placeholder is a strong
// sign, only hallpass hands it out; the value only catches the naive
// case (pass mode, or a token the sandbox read from a file).
func leaked(creds []Credential, host string, h http.Header) *Credential {
	for i := range creds {
		c := &creds[i]
		if c.forHost(host) {
			continue
		}
		for _, vs := range h {
			for _, v := range vs {
				if carries(v, c) {
					return c
				}
				if basic, ok := basicAuth(v); ok && carries(basic, c) {
					return c
				}
			}
		}
	}
	return nil
}

func carries(v string, c *Credential) bool {
	return (c.Placeholder != "" && strings.Contains(v, c.Placeholder)) || strings.Contains(v, c.Value)
}

// inject replaces, in the Authorization header of a request to host,
// the placeholders of the credentials for host by their values, inside
// Basic authorization too (git sends the token as a password). Only
// there: a server echoing another header (or storing it where the
// sandbox can read it back) must not get the value.
func inject(creds []Credential, host string, h http.Header) {
	for i := range creds {
		c := &creds[i]
		if c.Placeholder == "" || !c.forHost(host) {
			continue
		}
		vs := h.Values("Authorization")
		for j, v := range vs {
			if basic, ok := basicAuth(v); ok && strings.Contains(basic, c.Placeholder) {
				vs[j] = "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(basic, c.Placeholder, c.Value)))
				continue
			}
			vs[j] = strings.ReplaceAll(v, c.Placeholder, c.Value)
		}
	}
}

// scrub replaces the values of the credentials in response headers by
// their placeholders: a server echoing the request's authorization must
// not hand the value to the sandbox. Bodies are not read (cost).
func scrub(creds []Credential, h http.Header) {
	for i := range creds {
		c := &creds[i]
		if c.Placeholder == "" {
			continue
		}
		for _, vs := range h {
			for j, v := range vs {
				vs[j] = strings.ReplaceAll(v, c.Value, c.Placeholder)
			}
		}
	}
}

// basicAuth decodes a Basic authorization value: "user:password".
func basicAuth(v string) (string, bool) {
	scheme, enc, ok := strings.Cut(v, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", false
	}
	return string(b), true
}
