// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
