// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net/netip"
	"testing"
	"time"
)

func inet(proto uint16, ap string) Object {
	return Object{Inet: &InetObject{Proto: proto, Addr: netip.MustParseAddrPort(ap)}}
}

func netRule(t *testing.T, spec string, v Verdict, id uint64) Rule {
	t.Helper()
	m, err := ParseNet(spec)
	if err != nil {
		t.Fatalf("ParseNet(%q): %v", spec, err)
	}
	return Rule{ID: id, Ops: OpNet, Object: m, Verdict: v}
}

func TestParseNet(t *testing.T) {
	for _, s := range []string{
		"all", "*", "tcp:*", "*:443", "1.2.3.4", "tcp:1.2.3.4:443", "10.0.0.0/8",
		"udp:10.0.0.0/8:53", "[2001:db8::1]", "[2001:db8::1]:443", "[2001:db8::]/32",
		"tcp:[2001:db8::]/32:8000-8999", "unix:/run/x.sock", "unix:/run/**", "unix:@foo",
		"unix:@foo*", "unix:@*",
	} {
		m, err := ParseNet(s)
		if err != nil {
			t.Errorf("ParseNet(%q): %v", s, err)
			continue
		}
		if got := m.NetString(); got != s {
			t.Errorf("ParseNet(%q).NetString() = %q", s, got)
		}
	}
	for in, want := range map[string]string{
		"2001:db8::/32":       "[2001:db8::]/32",
		"[::ffff:127.0.0.1]":  "127.0.0.1",
		"::ffff:10.0.0.0/104": "10.0.0.0/8",
		"10.1.2.3/8":          "10.0.0.0/8",
		"unix:/run/../run/x":  "unix:/run/x",
		"unix:/**":            "unix:/**",
	} {
		m, err := ParseNet(in)
		if err != nil || m.NetString() != want {
			t.Errorf("ParseNet(%q) = %q, %v; want %q", in, m.NetString(), err, want)
		}
	}
	for _, s := range []string{"", "foo", "1.2.3.4:0", "1.2.3.4:70000", "1.2.3.4:9-8", "[::1", "unix:rel", "unix:@", "tcp:1.2.3.4:x"} {
		if _, err := ParseNet(s); err == nil {
			t.Errorf("ParseNet(%q): no error", s)
		}
	}
}

func TestEvalNet(t *testing.T) {
	rs := []Rule{
		netRule(t, "tcp:140.82.112.0/20:443", Allow, 1),
		netRule(t, "10.0.0.0/8", Deny, 2),
		netRule(t, "[2001:db8::]/32", Allow, 3),
		netRule(t, "*:53", Ask, 4),
		netRule(t, "unix:/run/**", Allow, 5),
		netRule(t, "unix:/run/docker.sock", Deny, 6),
		netRule(t, "unix:@dbus-*", Allow, 7),
		netRule(t, "udp:*", Allow, 8),
		{ID: 9, Ops: OpNet, Object: ObjectMatch{OwnListener: true}},
		netRule(t, "127.0.0.1:9", Ask, 10),
	}
	own := inet(6, "127.0.0.1:9")
	own.Inet.OwnListener = true
	for _, tc := range []struct {
		name string
		obj  Object
		v    Verdict
		id   uint64
		ok   bool
	}{
		{"cidr port proto", inet(6, "140.82.112.21:443"), Allow, 1, true},
		{"other port", inet(6, "140.82.112.21:80"), 0, 0, false},
		{"other proto", inet(17, "140.82.112.21:443"), Allow, 8, true},
		{"deny", inet(17, "10.1.2.3:53"), Deny, 2, true},
		{"v6", inet(6, "[2001:db8::1]:22"), Allow, 3, true},
		{"udp 53: ask deeper than udp:*", inet(17, "9.9.9.9:53"), Ask, 4, true},
		{"unix tree", Object{Unix: &UnixObject{Path: "/run/user/1/bus"}}, Allow, 5, true},
		{"unix deny", Object{Unix: &UnixObject{Path: "/run/docker.sock"}}, Deny, 6, true},
		{"unix outside", Object{Unix: &UnixObject{Path: "/tmp/x"}}, 0, 0, false},
		{"abstract prefix", Object{Unix: &UnixObject{Abstract: true, Name: "dbus-123"}}, Allow, 7, true},
		{"abstract other", Object{Unix: &UnixObject{Abstract: true, Name: "run"}}, 0, 0, false},
		{"abstract is not a path", Object{Unix: &UnixObject{Abstract: true, Name: "/run/x"}}, 0, 0, false},
		{"own listener beats ask", own, Allow, 9, true},
		{"not own", inet(6, "127.0.0.1:9"), Ask, 10, true},
	} {
		v, id, ok := Eval(rs, OpConnect, tc.obj, time.Time{})
		if v != tc.v || id != tc.id || ok != tc.ok {
			t.Errorf("%s: %v %d %v; want %v %d %v", tc.name, v, id, ok, tc.v, tc.id, tc.ok)
		}
	}
	// Net rules don't match files, path rules don't match sockets.
	if _, _, ok := Eval(rs, OpWrite, file("/run/x"), time.Time{}); ok {
		t.Error("a net rule matched a file")
	}
	all := []Rule{netRule(t, "all", Allow, 1), path("/", true, Deny, 2)}
	for _, o := range []Object{inet(6, "1.2.3.4:1"), inet(17, "[::1]:1"), {Unix: &UnixObject{Abstract: true, Name: "x"}}} {
		if v, id, ok := Eval(all, OpSend, o, time.Time{}); !ok || v != Allow || id != 1 {
			t.Errorf("all: %v: %v %d %v", o, v, id, ok)
		}
	}
	// Families stay apart: an IPv6 /0 is not an IPv4 rule.
	v6 := []Rule{netRule(t, "[::]/0", Allow, 1)}
	if _, _, ok := Eval(v6, OpConnect, inet(6, "1.2.3.4:1"), time.Time{}); ok {
		t.Error("::/0 matched an IPv4 address")
	}
}

func TestExactNet(t *testing.T) {
	o := inet(6, "[::ffff:1.2.3.4]:443")
	m := ExactNet(o)
	if got := m.NetString(); got != "1.2.3.4:443" {
		t.Errorf("ExactNet = %q", got)
	}
	r := []Rule{{Ops: OpNet, Object: m, Verdict: Allow}}
	if _, _, ok := Eval(r, OpConnect, inet(17, "1.2.3.4:443"), time.Time{}); !ok {
		t.Error("ExactNet of tcp does not match udp")
	}
	if _, _, ok := Eval(r, OpConnect, inet(6, "1.2.3.4:444"), time.Time{}); ok {
		t.Error("ExactNet matches another port")
	}
	u := Object{Unix: &UnixObject{Abstract: true, Name: "a"}}
	if got := ExactNet(u).NetString(); got != "unix:@a" {
		t.Errorf("ExactNet = %q", got)
	}
}

func TestCoversNet(t *testing.T) {
	for _, tc := range []struct {
		m, o            string
		covers, overlap bool
	}{
		{"all", "tcp:1.2.3.4:443", true, true},
		{"all", "unix:@x*", true, true},
		{"tcp:1.2.3.4:443", "all", false, true},
		{"*", "10.0.0.0/8", true, true},
		{"*", "[::1]:53", true, true},
		{"*", "unix:/a", false, false},
		{"10.0.0.0/8", "10.1.2.3:22", true, true},
		{"10.0.0.0/8", "10.0.0.0/7", false, true},
		{"10.0.0.0/8", "11.0.0.1", false, false},
		{"10.0.0.0/8", "*", false, true},
		{"10.0.0.0/8", "[::ffff:10.0.0.1]", true, true},
		{"10.0.0.0/8", "[::1]", false, false},
		// netip.Prefix.Contains and Overlaps are false across families.
		{"0.0.0.0/0", "[2001:db8::1]", false, false},
		{"[::]/0", "1.2.3.4", false, false},
		{"[2001:db8::]/32", "[2001:db8::1]:443", true, true},
		{"*:443", "1.2.3.4:443", true, true},
		{"*:443", "1.2.3.4", false, true},
		{"*:443", "1.2.3.4:80", false, false},
		{"*:8000-8999", "*:8080-8090", true, true},
		{"*:8000-8999", "*:7000-8000", false, true},
		{"tcp:*", "udp:*", false, false},
		{"tcp:*", "*", false, true},
		{"*", "tcp:1.2.3.4", true, true},
		{"unix:/run/**", "unix:/run/x.sock", true, true},
		{"unix:/run/**", "unix:/run/a/**", true, true},
		{"unix:/run/x.sock", "unix:/run/**", false, true},
		{"unix:/run/x.sock", "unix:/run/y.sock", false, false},
		{"unix:/run/x.sock", "unix:@x", false, false},
		{"unix:@foo*", "unix:@foobar", true, true},
		{"unix:@foo*", "unix:@fo*", false, true},
		{"unix:@foo", "unix:@foo*", false, true},
		{"unix:@foo", "unix:@bar", false, false},
	} {
		m, err := ParseNet(tc.m)
		if err != nil {
			t.Fatal(err)
		}
		o, err := ParseNet(tc.o)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.CoversNet(o); got != tc.covers {
			t.Errorf("%s covers %s: %v, want %v", tc.m, tc.o, got, tc.covers)
		}
		if got := m.OverlapsNet(o); got != tc.overlap {
			t.Errorf("%s overlaps %s: %v, want %v", tc.m, tc.o, got, tc.overlap)
		}
		if got := o.OverlapsNet(m); got != tc.overlap {
			t.Errorf("%s overlaps %s: %v, want %v", tc.o, tc.m, got, tc.overlap)
		}
	}
	own := ObjectMatch{OwnListener: true}
	tcp, _ := ParseNet("tcp:127.0.0.1:80")
	if own.CoversNet(tcp) || !own.OverlapsNet(tcp) || (ObjectMatch{Path: &PathMatch{Path: "/"}}).OverlapsNet(tcp) {
		t.Error("own listeners or a path")
	}
	if !own.CoversNet(own) || own.CoversNet(ObjectMatch{AnyNet: true}) || !(ObjectMatch{AnyNet: true}).CoversNet(own) {
		t.Error("own listeners cover only themselves")
	}
}
