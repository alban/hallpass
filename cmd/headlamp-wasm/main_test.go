// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/nodeclient"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionapi"
)

// portForward plays the API server's side of a port-forward WebSocket to
// target: it sends the port headers, then relays the data channel to and
// from a TCP connection, in small messages.
func portForward(t *testing.T, target string) *pfConn {
	t.Helper()
	tcp, err := net.Dial("tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	var pc *pfConn
	pc = newPFConn(func(msg []byte) error {
		if msg[0] != 0 {
			return errors.New("write on a channel other than data")
		}
		_, err := tcp.Write(msg[1:])
		return err
	})
	pc.deliver([]byte{0, 0x9b, 0x1c}) // port 7323
	pc.deliver([]byte{1, 0x9b, 0x1c})
	go func() {
		buf := make([]byte, 7) // splits gRPC frames across messages
		for {
			n, err := tcp.Read(buf)
			if n > 0 {
				pc.deliver(append([]byte{0}, buf[:n]...))
			}
			if err != nil {
				pc.closeWithError(err)
				return
			}
		}
	}()
	return pc
}

type session struct {
	name string

	mu      sync.Mutex
	answers []string
}

func (s *session) Info() *pb.SessionInfo {
	return &pb.SessionInfo{Labels: map[string]string{"namespace": "ns", "pod": s.name, "container": "c"}}
}
func (s *session) Prompt(*monitor.Request) *pb.Prompt { return &pb.Prompt{} }
func (s *session) CheckRules(string, []rules.Rule, []rules.Rule, []rules.Rule) error {
	return nil
}
func (s *session) RulesChanged(string, []rules.Rule, []rules.Rule) {}
func (s *session) Answer(id uint64, answer, client string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.answers = append(s.answers, answer+" "+client)
	if id != 42 {
		return monitor.ErrClosed
	}
	return nil
}

func TestNodeOverPortForward(t *testing.T) {
	h := sessionapi.NewNode()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve(ln) }()
	defer h.Stop()
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	sess := &session{name: "agent"}
	h.Add("s1", m, sess)

	pc := portForward(t, ln.Addr().String())
	conn, c, err := nodeclient.DialConn(pc)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	states := make(chan nodeclient.State, 10)
	go func() {
		_ = nodeclient.Watch(ctx, c, time.Second, func(st nodeclient.State) { states <- st })
	}()
	select {
	case st := <-states:
		if len(st.Sessions) != 1 || nodeclient.Name(st.Sessions[0].Info) != "ns/agent/c" {
			t.Fatalf("state: %v", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no state")
	}

	actx, acancel := context.WithTimeout(nodeclient.WithSession(ctx, "s1"), 10*time.Second)
	defer acancel()
	if _, err := c.Answer(actx, &pb.AnswerRequest{Request: 42, Answer: "once", Client: "headlamp"}); err != nil {
		t.Fatalf("Answer: %v", err)
	}
	if _, err := c.Answer(actx, &pb.AnswerRequest{Request: 43, Answer: "deny"}); err == nil {
		t.Error("Answer of a request not pending succeeded")
	}
	sess.mu.Lock()
	got := strings.Join(sess.answers, ",")
	sess.mu.Unlock()
	if got != "once headlamp,deny " {
		t.Errorf("answers: %q", got)
	}

	// The stream carries one connection: once it closes, calls fail
	// rather than reconnect.
	pc.closeWithError(io.EOF)
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := c.List(ctx, &pb.ListRequest{})
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("List still works after the port-forward closed")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestPFConn(t *testing.T) {
	var sent [][]byte
	pc := newPFConn(func(b []byte) error { sent = append(sent, b); return nil })
	pc.deliver([]byte{0, 1, 2, 'a', 'b'}) // header and data in one message
	pc.deliver([]byte{1, 1, 2})
	pc.deliver([]byte{0, 'c'})
	buf := make([]byte, 1)
	var got []byte
	for range 3 {
		n, err := pc.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if string(got) != "abc" {
		t.Errorf("read %q, want abc", got)
	}
	if _, err := pc.Write([]byte("xy")); err != nil || len(sent) != 1 || string(sent[0]) != "\x00xy" {
		t.Errorf("Write: %v, sent %q", err, sent)
	}

	pc.deliver([]byte{1, 'n', 'o', ' ', 'p', 'o', 'd'})
	if _, err := pc.Read(buf); err == nil || !strings.Contains(err.Error(), "no pod") {
		t.Errorf("Read after an error message: %v", err)
	}
	if _, err := pc.Write([]byte("z")); err == nil {
		t.Error("Write after close succeeded")
	}

	// Writes wait for the port header: the WebSocket is not open before.
	sentc := make(chan []byte, 1)
	pc = newPFConn(func(b []byte) error { sentc <- b; return nil })
	go func() { _, _ = pc.Write([]byte("early")) }()
	select {
	case <-sentc:
		t.Fatal("Write sent before the port header")
	case <-time.After(50 * time.Millisecond):
	}
	pc.deliver([]byte{0, 1, 2})
	select {
	case b := <-sentc:
		if string(b) != "\x00early" {
			t.Errorf("sent %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not send after the port header")
	}
}
