// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/alban/hallpass/internal/monitor"
	pb "github.com/alban/hallpass/internal/sessionpb"
)

type fakeSession struct{}

func (fakeSession) Info() *pb.SessionInfo {
	return &pb.SessionInfo{Pid: int32(os.Getpid()), Mode: "lite"}
}
func (fakeSession) Prompt(*monitor.Request) *pb.Prompt  { return &pb.Prompt{} }
func (fakeSession) Answer(uint64, string, string) error { return monitor.ErrClosed }

func listen(t *testing.T) *Server {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := Listen(m, fakeSession{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestDial(t *testing.T) {
	s := listen(t)
	conn, c, err := Dial(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	info, err := c.Info(context.Background(), &pb.InfoRequest{})
	if err != nil || info.Pid != int32(os.Getpid()) {
		t.Fatalf("Info: %v, %v", info, err)
	}
	if _, err := c.Answer(context.Background(), &pb.AnswerRequest{Request: 1, Answer: "once"}); err == nil {
		t.Error("Answer of an unknown request succeeded")
	}
}

// TestDialWrongPID checks that a client refuses a socket whose name is not
// its server's pid: a fake session.
func TestDialWrongPID(t *testing.T) {
	s := listen(t)
	fake := filepath.Join(SocketDir(), "1.sock")
	if err := os.Symlink(s.Path(), fake); err != nil {
		t.Fatal(err)
	}
	conn, c, err := Dial(fake)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = c.Info(context.Background(), &pb.InfoRequest{})
	if err == nil || !strings.Contains(err.Error(), "not a hallpass session") {
		t.Fatalf("Info: %v, want a refusal", err)
	}
}

func TestListSocket(t *testing.T) {
	s := listen(t)
	conn, c, err := Dial(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	l, err := c.List(context.Background(), &pb.ListRequest{})
	if err != nil || len(l.Sessions) != 1 || l.Sessions[0].Pid != int32(os.Getpid()) {
		t.Fatalf("List: %v, %v", l, err)
	}
}

type labeled struct {
	fakeSession
	name string
}

func (l labeled) Info() *pb.SessionInfo {
	return &pb.SessionInfo{Labels: map[string]string{"name": l.name}}
}

func TestHub(t *testing.T) {
	h := NewHub()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = h.Serve(ln) }()
	defer h.Stop()
	for _, id := range []string{"b", "a"} {
		m, err := monitor.New(monitor.Config{})
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		h.Add(id, m, labeled{name: "session " + id})
	}

	conn, c, err := DialHub(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	l, err := c.List(ctx, &pb.ListRequest{})
	if err != nil || len(l.Sessions) != 2 || l.Sessions[0].Id != "a" || l.Sessions[1].Labels["name"] != "session b" {
		t.Fatalf("List: %v, %v", l, err)
	}
	info, err := c.Info(WithSession(ctx, "b"), &pb.InfoRequest{})
	if err != nil || info.Labels["name"] != "session b" {
		t.Fatalf("Info: %v, %v", info, err)
	}
	if _, err := c.Snapshot(WithSession(ctx, "a"), &pb.SnapshotRequest{}); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := c.Info(ctx, &pb.InfoRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Info without a session: %v", err)
	}
	h.Remove("b")
	if _, err := c.Info(WithSession(ctx, "b"), &pb.InfoRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("Info of a removed session: %v", err)
	}
}
