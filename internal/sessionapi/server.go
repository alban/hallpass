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
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rulepb"
	"github.com/alban/hallpass/internal/rules"
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

// ensureSocketDir creates dir, a directory of this user only (0700). Without
// XDG_RUNTIME_DIR it is in the shared os.TempDir(), where another user could
// have created it first, or put a symlink there: an existing dir must be a
// directory owned by this user, and it is made 0700.
func ensureSocketDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket directory %s: %w", dir, err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("socket directory %s: %w", dir, err)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("socket directory %s is owned by uid %d, not by this user", dir, st.Uid)
	}
	if st.Mode&0o777 != 0o700 {
		if err := unix.Fchmod(fd, 0o700); err != nil {
			return fmt.Errorf("socket directory %s: %w", dir, err)
		}
	}
	return nil
}

// Session is what the server needs from the session beyond its monitor.
type Session interface {
	Info() *pb.SessionInfo
	// Prompt describes a request the way the session's prompt does.
	Prompt(*monitor.Request) *pb.Prompt
	// Answer answers request id with the session's policy; it fails with
	// monitor.ErrClosed if the request is not pending.
	Answer(id uint64, answer, client string) error
	// CheckRules checks that client may remove the rules removed and add
	// the rules add (validated by the monitor already, their paths
	// resolved), next being the rules after the change; it fails with
	// answer.ErrTooWide if the session's policy does not let it. The
	// monitor is locked: CheckRules must not call it.
	CheckRules(client string, add, removed, next []rules.Rule) error
	// RulesChanged reports that client removed and added rules, after
	// CheckRules.
	RulesChanged(client string, add, removed []rules.Rule)
}

// Server serves a session on its socket.
type Server struct {
	service
	srv  *grpc.Server
	path string
	// quit ends the streams (Close).
	quit      chan struct{}
	closeOnce sync.Once
}

// entry is a served session.
type entry struct {
	m    *monitor.Monitor
	sess Session
}

// service implements the API on the sessions that lookup finds.
type service struct {
	pb.UnimplementedSessionServer
	// lookup returns the session a call is for.
	lookup func(context.Context) (entry, error)
	// list describes the sessions served.
	list func() []*pb.SessionInfo
}

// Listen serves sess and m on SocketPath(os.Getpid()).
func Listen(m *monitor.Monitor, sess Session) (*Server, error) {
	if err := ensureSocketDir(SocketDir()); err != nil {
		return nil, err
	}
	path := SocketPath(os.Getpid())
	_ = os.Remove(path)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	e := entry{m: m, sess: sess}
	s := &Server{path: path, quit: make(chan struct{})}
	s.lookup = func(context.Context) (entry, error) { return e, nil }
	s.list = func() []*pb.SessionInfo { return []*pb.SessionInfo{sess.Info()} }
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
			ctx, cancel := context.WithCancel(ss.Context())
			defer cancel()
			go func() {
				select {
				case <-s.quit:
					cancel()
				case <-ctx.Done():
				}
			}()
			return h(srv, &stream{ServerStream: ss, ctx: ctx})
		}),
	)
	pb.RegisterSessionServer(s.srv, &s.service)
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Close stops serving and removes the socket. The calls in progress
// finish first: an answer that lets the command exit still gets its
// reply. The streams (events, prompts) are ended; whatever is left after
// closeGrace is cut.
func (s *Server) Close() {
	s.closeOnce.Do(func() {
		close(s.quit)
		done := make(chan struct{})
		go func() {
			s.srv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(closeGrace):
			s.srv.Stop()
		}
		_ = os.Remove(s.path)
	})
}

// closeGrace bounds how long Close waits for the calls in progress.
const closeGrace = time.Second

// stream is a grpc.ServerStream with its own context, ended by Close.
type stream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *stream) Context() context.Context { return s.ctx }

func (s *service) Info(ctx context.Context, _ *pb.InfoRequest) (*pb.SessionInfo, error) {
	e, err := s.lookup(ctx)
	if err != nil {
		return nil, err
	}
	return e.sess.Info(), nil
}

func (s *service) List(context.Context, *pb.ListRequest) (*pb.ListReply, error) {
	return &pb.ListReply{Sessions: s.list()}, nil
}

func (e entry) snapshot() *pb.SnapshotReply {
	pending, rs, gen := e.m.Snapshot()
	out := &pb.SnapshotReply{Generation: gen}
	for _, r := range pending {
		out.Pending = append(out.Pending, toPBRequest(r, e.sess.Prompt(r)))
	}
	for _, r := range rs {
		out.Rules = append(out.Rules, rulepb.To(r))
	}
	return out
}

func (s *service) Snapshot(ctx context.Context, _ *pb.SnapshotRequest) (*pb.SnapshotReply, error) {
	e, err := s.lookup(ctx)
	if err != nil {
		return nil, err
	}
	return e.snapshot(), nil
}

func (s *service) Events(req *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.EventBatch]) error {
	ctx := stream.Context()
	e, err := s.lookup(ctx)
	if err != nil {
		return err
	}
	evs := e.m.Events(monitor.EventOptions{Decided: req.GetDecided(), Done: ctx.Done()})
	if req.GetSnapshot() {
		if err := stream.Send(&pb.EventBatch{Snapshot: e.snapshot()}); err != nil {
			return err
		}
	}
	for batch := range evs {
		out := &pb.EventBatch{}
		for _, ev := range batch {
			pe := &pb.Event{}
			switch {
			case ev.Opened != nil:
				pe.Kind = &pb.Event_Opened{Opened: toPBRequest(ev.Opened, e.sess.Prompt(ev.Opened))}
			case ev.Closed != nil:
				pe.Kind = &pb.Event_Closed{Closed: &pb.Closed{Id: ev.Closed.ID, Why: toPBReason(ev.Closed.Why)}}
			case ev.Rules != 0:
				pe.Kind = &pb.Event_Rules{Rules: ev.Rules}
			case ev.Decided != nil:
				pe.Kind = &pb.Event_Decided{Decided: toPBDecided(ev.Decided)}
			case ev.Warning != "":
				pe.Kind = &pb.Event_Warning{Warning: ev.Warning}
			case ev.Dropped != 0:
				pe.Kind = &pb.Event_Dropped{Dropped: ev.Dropped}
			case ev.Released != nil:
				r := &pb.Released{Subject: toPBSubject(ev.Released.Subject)}
				for _, rule := range ev.Released.Rules {
					r.Rules = append(r.Rules, rulepb.To(rule))
				}
				pe.Kind = &pb.Event_Released{Released: r}
			default:
				continue
			}
			out.Events = append(out.Events, pe)
		}
		if err := stream.Send(out); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *service) Apply(ctx context.Context, d *pb.Decision) (*pb.ApplyReply, error) {
	e, err := s.lookup(ctx)
	if err != nil {
		return nil, err
	}
	md, err := fromPBDecision(d)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	gen, err := ApplyRules(e.m, e.sess, md)
	if err != nil {
		return nil, err
	}
	return &pb.ApplyReply{Generation: gen}, nil
}

// ApplyRules applies d to m like Apply does, for clients in the session's
// own process: the rules it adds and removes are checked with sess's policy
// first. Errors are gRPC statuses.
func ApplyRules(m *monitor.Monitor, sess Session, d monitor.Decision) (uint64, error) {
	if len(d.AddRules)+len(d.RemoveRules)+len(d.RemoveSets) == 0 {
		gen, err := m.Apply(d)
		if err != nil {
			return 0, toStatus(err)
		}
		return gen, nil
	}
	if err := checkRules(m, d.AddRules); err != nil {
		return 0, err
	}
	var added, removed []rules.Rule
	d.Check = func(add, rm, next []rules.Rule) error {
		added, removed = add, rm
		return sess.CheckRules(d.Client, add, rm, next)
	}
	gen, err := m.Apply(d)
	if err != nil {
		return 0, toStatus(err)
	}
	if len(added)+len(removed) > 0 {
		sess.RulesChanged(d.Client, added, removed)
	}
	return gen, nil
}

// checkRules validates the rules a client adds, so that a malformed rule is
// InvalidArgument. Apply checks them again, with the session's policy, as
// it resolves their paths: a path the sandbox changes in between cannot
// slip through.
func checkRules(m *monitor.Monitor, add []rules.Rule) error {
	for _, r := range add {
		if err := m.Check(&r); err != nil {
			if s := toStatus(err); status.Code(s) != codes.Unknown {
				return s
			}
			return status.Error(codes.InvalidArgument, err.Error())
		}
	}
	return nil
}

func (s *service) Answer(ctx context.Context, a *pb.AnswerRequest) (*pb.AnswerReply, error) {
	e, err := s.lookup(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.sess.Answer(a.GetRequest(), a.GetAnswer(), a.GetClient()); err != nil {
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
	case errors.Is(err, monitor.ErrProtected), errors.Is(err, answer.ErrTooWide):
		return status.Error(codes.PermissionDenied, err.Error())
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
