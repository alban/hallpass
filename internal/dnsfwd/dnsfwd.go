// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package dnsfwd relays the DNS queries of one container to its name
// servers, and records the answers (dnsnames.Names.AnswerMsg): the names
// in its prompts are those of the answers it got. hallpass-node starts
// one forwarder per mediated container, its listeners on the loopback of
// the container's network namespace; internal/dnsredirect sends the
// container's queries there.
//
// Upstream sockets are made in the container's network namespace too, so
// queries leave from the pod's address: NetworkPolicy and the cluster's
// DNS policies apply as if the pod asked. Messages are relayed byte for
// byte, the truncation bit included: the client retries over TCP itself.
// The servers are fixed when the forwarder starts, whatever the
// container writes to its resolv.conf later.
package dnsfwd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/alban/hallpass/internal/dnsnames"
	"golang.org/x/net/dns/dnsmessage"
)

// Bounds and timeouts.
const (
	// maxUpstreams bounds the UDP clients relayed at once, per server.
	maxUpstreams = 64
	// udpIdle closes the upstream socket of a UDP client this long after
	// its last query or reply.
	udpIdle = 30 * time.Second
	// tcpIdle closes a TCP connection idle this long.
	tcpIdle = 2 * time.Minute
	// maxTCPConns bounds the TCP connections relayed at once, per server.
	maxTCPConns = 64
	dialTimeout = 5 * time.Second
	maxMsg      = 65535
)

// Dialer makes the upstream sockets: in the container's network
// namespace (netns.Worker.Do).
type Dialer func(f func() error) error

// Listener is a server's listener: where internal/dnsredirect sends the
// queries to Server, port 53.
type Listener struct {
	Server netip.Addr
	Addr   netip.AddrPort
}

// Forwarder relays the queries of one container.
type Forwarder struct {
	names *dnsnames.Names
	in    Dialer
	warn  func(string)

	mu      sync.Mutex
	closed  bool
	servers []*server
}

type server struct {
	f     *Forwarder
	addr  netip.AddrPort // the name server, port 53
	udp   *net.UDPConn
	tcp   *net.TCPListener
	local netip.AddrPort

	mu    sync.Mutex
	ups   map[netip.AddrPort]*upstream // by client
	conns map[net.Conn]bool
}

type upstream struct {
	c    *net.UDPConn
	last time.Time
	// pending are the queries sent and not answered yet (queryKey):
	// a reply matching none is dropped, not recorded. Guarded by
	// server.mu.
	pending map[string]bool
}

// maxPending bounds the queries of one client awaiting replies.
const maxPending = 64

// queryKey identifies a DNS message's transaction: its ID and first
// question; "" for what is not a DNS message with a question.
func queryKey(msg []byte, response bool) string {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || h.Response != response {
		return ""
	}
	q, err := p.Question()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d\x00%s\x00%d\x00%d", h.ID, strings.ToLower(q.Name.String()), q.Type, q.Class)
}

// Start starts relaying to servers (port 53 but in tests): one listener
// per server, on 127.0.0.1 (IPv4 server, or IPv4-mapped) or [::1] (IPv6),
// UDP and TCP on the same port, made with in. Answers are recorded in
// names; warn logs what fails later.
func Start(in Dialer, servers []netip.AddrPort, names *dnsnames.Names, warn func(string)) (*Forwarder, error) {
	f := &Forwarder{names: names, in: in, warn: warn}
	for _, ap := range servers {
		a := ap.Addr().Unmap()
		if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() {
			continue
		}
		s, err := f.listen(netip.AddrPortFrom(a, ap.Port()))
		if err != nil {
			f.Close()
			return nil, err
		}
		f.servers = append(f.servers, s)
	}
	if len(f.servers) == 0 {
		return nil, errors.New("dnsfwd: no name server")
	}
	for _, s := range f.servers {
		go s.serveUDP()
		go s.serveTCP()
	}
	return f, nil
}

// listen makes the UDP and TCP listeners of s, on one port the kernel
// picks: free in the namespace, so the listeners of several containers of
// one pod never clash.
func (f *Forwarder) listen(addr netip.AddrPort) (*server, error) {
	lo := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	network := "4"
	if addr.Addr().Is6() {
		lo, network = netip.IPv6Loopback(), "6"
	}
	s := &server{f: f, addr: addr, ups: map[netip.AddrPort]*upstream{}, conns: map[net.Conn]bool{}}
	var err error
	for range 16 {
		err = f.in(func() error {
			u, err := net.ListenUDP("udp"+network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(lo, 0)))
			if err != nil {
				return err
			}
			local := netip.MustParseAddrPort(u.LocalAddr().String())
			t, err := net.ListenTCP("tcp"+network, net.TCPAddrFromAddrPort(local))
			if err != nil {
				u.Close()
				return err
			}
			s.udp, s.tcp, s.local = u, t, local
			return nil
		})
		if err == nil {
			return s, nil
		}
		// The TCP port was taken: another try.
	}
	return nil, fmt.Errorf("dnsfwd: listen for %v: %w", addr, err)
}

// Listeners returns the listeners, one per server.
func (f *Forwarder) Listeners() []Listener {
	var out []Listener
	for _, s := range f.servers {
		out = append(out, Listener{Server: s.addr.Addr(), Addr: s.local})
	}
	return out
}

// Close stops relaying.
func (f *Forwarder) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	f.mu.Unlock()
	for _, s := range f.servers {
		s.udp.Close()
		s.tcp.Close()
		s.mu.Lock()
		for _, u := range s.ups {
			u.c.Close()
		}
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	}
}

func (f *Forwarder) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// serveUDP relays each client's datagrams through an upstream socket of
// its own, connected to the server: the replies come back to that client.
func (s *server) serveUDP() {
	b := make([]byte, maxMsg)
	for {
		k, client, err := s.udp.ReadFromUDPAddrPort(b)
		if err != nil {
			if !s.f.isClosed() && !errors.Is(err, net.ErrClosed) {
				s.f.warn("dns forwarder: " + err.Error())
			}
			return
		}
		key := queryKey(b[:k], false)
		if key == "" {
			continue
		}
		u, err := s.upstream(client)
		if err != nil {
			s.f.warn("dns forwarder: " + err.Error())
			continue
		}
		s.mu.Lock()
		if len(u.pending) >= maxPending {
			clear(u.pending)
		}
		u.pending[key] = true
		s.mu.Unlock()
		if _, err := u.c.Write(b[:k]); err != nil {
			s.f.warn("dns forwarder: " + err.Error())
		}
	}
}

// upstream returns the upstream socket of client, making it (and its
// reader) on the first query.
func (s *server) upstream(client netip.AddrPort) (*upstream, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if u := s.ups[client]; u != nil {
		u.last = now
		return u, nil
	}
	if len(s.ups) >= maxUpstreams {
		for k, u := range s.ups {
			if now.Sub(u.last) >= udpIdle {
				u.c.Close()
				delete(s.ups, k)
			}
		}
		if len(s.ups) >= maxUpstreams {
			return nil, fmt.Errorf("%d clients at once", len(s.ups))
		}
	}
	var c *net.UDPConn
	err := s.f.in(func() (err error) {
		c, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(s.addr))
		return err
	})
	if err != nil {
		return nil, err
	}
	u := &upstream{c: c, last: now, pending: map[string]bool{}}
	s.ups[client] = u
	go s.replies(client, u)
	return u, nil
}

// replies passes the server's replies on to client, until the upstream
// socket is idle for udpIdle.
func (s *server) replies(client netip.AddrPort, u *upstream) {
	defer func() {
		s.mu.Lock()
		if s.ups[client] == u {
			delete(s.ups, client)
		}
		s.mu.Unlock()
		u.c.Close()
	}()
	b := make([]byte, maxMsg)
	for {
		s.mu.Lock()
		deadline := u.last.Add(udpIdle)
		s.mu.Unlock()
		u.c.SetReadDeadline(deadline)
		k, err := u.c.Read(b)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				s.mu.Lock()
				idle := !time.Now().Before(u.last.Add(udpIdle))
				s.mu.Unlock()
				if !idle {
					continue
				}
			}
			return
		}
		// Only the reply to a query sent: a forged one (the container
		// can send to the upstream socket's port in its namespace) is
		// dropped. Recorded before the client reads it.
		key := queryKey(b[:k], true)
		s.mu.Lock()
		ok := key != "" && u.pending[key]
		delete(u.pending, key)
		u.last = time.Now()
		s.mu.Unlock()
		if !ok {
			continue
		}
		s.f.names.AnswerMsg(b[:k])
		if _, err := s.udp.WriteToUDPAddrPort(b[:k], client); err != nil && !s.f.isClosed() {
			s.f.warn("dns forwarder: " + err.Error())
		}
	}
}

// serveTCP relays each TCP connection to a connection to the server.
func (s *server) serveTCP() {
	for {
		c, err := s.tcp.AcceptTCP()
		if err != nil {
			if !s.f.isClosed() && !errors.Is(err, net.ErrClosed) {
				s.f.warn("dns forwarder: " + err.Error())
			}
			return
		}
		s.mu.Lock()
		full := len(s.conns) >= maxTCPConns
		if !full {
			s.conns[c] = true
		}
		s.mu.Unlock()
		if full {
			c.Close()
			continue
		}
		go s.relayTCP(c)
	}
}

func (s *server) relayTCP(c *net.TCPConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
		c.Close()
	}()
	var up *net.TCPConn
	err := s.f.in(func() error {
		d := net.Dialer{Timeout: dialTimeout}
		uc, err := d.Dial("tcp", s.addr.String())
		if err == nil {
			up = uc.(*net.TCPConn)
		}
		return err
	})
	if err != nil {
		return
	}
	defer up.Close()
	s.mu.Lock()
	s.conns[up] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.conns, up)
		s.mu.Unlock()
	}()
	var mu sync.Mutex
	pending := map[string]bool{}
	go func() {
		// Queries: message by message, noted, passed on. A client
		// done sending still reads its replies.
		defer up.CloseWrite()
		var hdr [2]byte
		b := make([]byte, maxMsg)
		for {
			c.SetReadDeadline(time.Now().Add(tcpIdle))
			if _, err := io.ReadFull(c, hdr[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(hdr[:]))
			if _, err := io.ReadFull(c, b[:n]); err != nil {
				return
			}
			if key := queryKey(b[:n], false); key != "" {
				mu.Lock()
				if len(pending) >= maxPending {
					clear(pending)
				}
				pending[key] = true
				mu.Unlock()
			}
			if _, err := up.Write(append(hdr[:], b[:n]...)); err != nil {
				return
			}
		}
	}()
	// Replies: read message by message, recorded when they answer a
	// query sent, then passed on. When they end, so does the connection.
	var hdr [2]byte
	b := make([]byte, maxMsg)
	for {
		up.SetReadDeadline(time.Now().Add(tcpIdle))
		if _, err := io.ReadFull(up, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(up, b[:n]); err != nil {
			return
		}
		key := queryKey(b[:n], true)
		mu.Lock()
		ok := key != "" && pending[key]
		delete(pending, key)
		mu.Unlock()
		if ok {
			s.f.names.AnswerMsg(b[:n])
		}
		if _, err := c.Write(append(hdr[:], b[:n]...)); err != nil {
			return
		}
	}
}
