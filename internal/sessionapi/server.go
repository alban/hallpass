// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package sessionapi serves a hallpass session's API (package sessionpb)
// on its unix socket, and connects to it.
package sessionapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/alban/hallpass/internal/monitor"
	pb "github.com/alban/hallpass/internal/sessionpb"
)

// SocketDir returns the directory holding the sessions' sockets.
func SocketDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "hallpass")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("hallpass-%d", os.Getuid()))
}

// SocketPath returns the socket of the session supervised by pid.
func SocketPath(pid int) string {
	return filepath.Join(SocketDir(), strconv.Itoa(pid)+".sock")
}

// Session is what the server needs from the session beyond its monitor.
type Session interface {
	Info() *pb.SessionInfo
	// Prompt describes a request the way the session's prompt does.
	Prompt(*monitor.Request) *pb.Prompt
	// Answer answers request id with the session's policy; it fails with
	// monitor.ErrClosed if the request is not pending.
	Answer(id uint64, answer, client string) error
}

// Server serves a session on its socket.
type Server struct {
	pb.UnimplementedSessionServer
	m    *monitor.Monitor
	sess Session
	srv  *grpc.Server
	path string
}

// Listen serves sess and m on SocketPath(os.Getpid()).
func Listen(m *monitor.Monitor, sess Session) (*Server, error) {
	dir := SocketDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := SocketPath(os.Getpid())
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	s := &Server{m: m, sess: sess, path: path}
	s.srv = grpc.NewServer(
		grpc.Creds(peerCreds{}),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if err := checkAuth(ctx); err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
		grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			if err := checkAuth(ss.Context()); err != nil {
				return err
			}
			return h(srv, ss)
		}),
	)
	pb.RegisterSessionServer(s.srv, s)
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Close stops serving and removes the socket.
func (s *Server) Close() {
	s.srv.Stop()
	_ = os.Remove(s.path)
}

func (s *Server) Info(context.Context, *pb.InfoRequest) (*pb.SessionInfo, error) {
	return s.sess.Info(), nil
}

func (s *Server) snapshot() *pb.SnapshotReply {
	pending, rs, gen := s.m.Snapshot()
	out := &pb.SnapshotReply{Generation: gen}
	for _, r := range pending {
		out.Pending = append(out.Pending, toPBRequest(r, s.sess.Prompt(r)))
	}
	for _, r := range rs {
		out.Rules = append(out.Rules, toPBRule(r))
	}
	return out
}

func (s *Server) Snapshot(context.Context, *pb.SnapshotRequest) (*pb.SnapshotReply, error) {
	return s.snapshot(), nil
}

func (s *Server) Events(req *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.EventBatch]) error {
	ctx := stream.Context()
	evs := s.m.Events(monitor.EventOptions{Decided: req.GetDecided(), Done: ctx.Done()})
	if req.GetSnapshot() {
		if err := stream.Send(&pb.EventBatch{Snapshot: s.snapshot()}); err != nil {
			return err
		}
	}
	for batch := range evs {
		out := &pb.EventBatch{}
		for _, ev := range batch {
			e := &pb.Event{}
			switch {
			case ev.Opened != nil:
				e.Kind = &pb.Event_Opened{Opened: toPBRequest(ev.Opened, s.sess.Prompt(ev.Opened))}
			case ev.Closed != nil:
				e.Kind = &pb.Event_Closed{Closed: &pb.Closed{Id: ev.Closed.ID, Why: toPBReason(ev.Closed.Why)}}
			case ev.Rules != 0:
				e.Kind = &pb.Event_Rules{Rules: ev.Rules}
			case ev.Decided != nil:
				e.Kind = &pb.Event_Decided{Decided: toPBDecided(ev.Decided)}
			case ev.Warning != "":
				e.Kind = &pb.Event_Warning{Warning: ev.Warning}
			case ev.Dropped != 0:
				e.Kind = &pb.Event_Dropped{Dropped: ev.Dropped}
			default:
				continue
			}
			out.Events = append(out.Events, e)
		}
		if err := stream.Send(out); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *Server) Apply(_ context.Context, d *pb.Decision) (*pb.ApplyReply, error) {
	md, err := fromPBDecision(d)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	gen, err := s.m.Apply(md)
	if err != nil {
		return nil, toStatus(err)
	}
	return &pb.ApplyReply{Generation: gen}, nil
}

func (s *Server) Answer(_ context.Context, a *pb.AnswerRequest) (*pb.AnswerReply, error) {
	if err := s.sess.Answer(a.GetRequest(), a.GetAnswer(), a.GetClient()); err != nil {
		return nil, toStatus(err)
	}
	return &pb.AnswerReply{}, nil
}

// ErrBadAnswer is returned by Session.Answer for an unknown answer.
var ErrBadAnswer = errors.New("unknown answer")

func toStatus(err error) error {
	switch {
	case errors.Is(err, monitor.ErrStale):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, monitor.ErrClosed):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, monitor.ErrUnsupported), errors.Is(err, ErrBadAnswer):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Unknown, err.Error())
}

// Dial connects to the session socket at path. The calls fail unless the
// socket is served by an unsandboxed process of the same user, the one
// whose pid names it (see SocketPath).
func Dial(path string) (*grpc.ClientConn, pb.SessionClient, error) {
	pid, _ := strconv.Atoi(strings.TrimSuffix(filepath.Base(path), ".sock"))
	conn, err := grpc.NewClient("unix://"+path,
		grpc.WithTransportCredentials(serverCreds{pid: pid}),
		// The default backoff is up to 2 minutes: the session is local.
		grpc.WithConnectParams(connectParams))
	if err != nil {
		return nil, nil, err
	}
	return conn, pb.NewSessionClient(conn), nil
}
