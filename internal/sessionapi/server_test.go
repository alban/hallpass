// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/nodeclient"
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

// TestSocketDirFallback checks the socket directory in os.TempDir(), used
// without XDG_RUNTIME_DIR: it must be this user's only.
func TestSocketDirFallback(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tmp)
	dir := SocketDir()
	if want := filepath.Join(tmp, fmt.Sprintf("hallpass-%d", os.Getuid())); dir != want {
		t.Fatalf("SocketDir = %s, want %s", dir, want)
	}
	perm := func() os.FileMode {
		t.Helper()
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Mode().Perm()
	}

	if err := ensureSocketDir(dir); err != nil {
		t.Fatalf("new dir: %v", err)
	}
	if p := perm(); p != 0o700 {
		t.Errorf("new dir: mode %o, want 700", p)
	}

	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketDir(dir); err != nil {
		t.Fatalf("own 0755 dir: %v", err)
	}
	if p := perm(); p != 0o700 {
		t.Errorf("own 0755 dir: mode %o, want 700", p)
	}

	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketDir(dir); err == nil {
		t.Error("symlink: accepted")
	}

	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketDir(dir); err == nil {
		t.Error("regular file: accepted")
	}

	if os.Getuid() != 0 {
		t.Log("not root: skipping the dir of another user")
		return
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := ensureSocketDir(dir); err == nil || !strings.Contains(err.Error(), "owned by uid 65534") {
		t.Errorf("dir of another user: %v, want a refusal", err)
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

func TestNode(t *testing.T) {
	h := NewNode()
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

	conn, c, err := nodeclient.Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	l, err := c.List(ctx, &pb.ListRequest{})
	if err != nil || len(l.Sessions) != 2 || l.Sessions[0].Id != "a" || l.Sessions[1].Labels["name"] != "session b" {
		t.Fatalf("List: %v, %v", l, err)
	}
	info, err := c.Info(nodeclient.WithSession(ctx, "b"), &pb.InfoRequest{})
	if err != nil || info.Labels["name"] != "session b" {
		t.Fatalf("Info: %v, %v", info, err)
	}
	if _, err := c.Snapshot(nodeclient.WithSession(ctx, "a"), &pb.SnapshotRequest{}); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if _, err := c.Info(ctx, &pb.InfoRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("Info without a session: %v", err)
	}
	h.Remove("b")
	if _, err := c.Info(nodeclient.WithSession(ctx, "b"), &pb.InfoRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("Info of a removed session: %v", err)
	}
}
