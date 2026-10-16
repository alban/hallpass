// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"net"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/alban/hallpass/internal/monitor"
	pb "github.com/alban/hallpass/internal/sessionpb"
)

// SessionKey is the gRPC metadata that selects a session on a Hub.
const SessionKey = "hallpass-session"

// Hub serves several sessions on one listener (the node agent's): List
// describes them, the other calls select one with the SessionKey metadata.
type Hub struct {
	service
	srv *grpc.Server

	mu       sync.Mutex
	sessions map[string]entry
}

// NewHub returns a hub serving no session.
func NewHub() *Hub {
	h := &Hub{sessions: map[string]entry{}}
	h.lookup = h.find
	h.list = h.infos
	h.srv = grpc.NewServer()
	pb.RegisterSessionServer(h.srv, &h.service)
	return h
}

// Add serves sess and m as session id.
func (h *Hub) Add(id string, m *monitor.Monitor, sess Session) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sessions[id] = entry{m: m, sess: sess}
}

// Remove stops serving session id; calls in progress go on.
func (h *Hub) Remove(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sessions, id)
}

// Serve serves ln until Stop. Unlike a session's socket (Listen), the
// clients are not checked: ln must only be reachable by trusted clients,
// e.g. on the loopback of the node agent's pod network.
func (h *Hub) Serve(ln net.Listener) error { return h.srv.Serve(ln) }

// Stop stops serving.
func (h *Hub) Stop() { h.srv.Stop() }

func (h *Hub) find(ctx context.Context) (entry, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	ids := md.Get(SessionKey)
	if len(ids) != 1 {
		return entry{}, status.Errorf(codes.InvalidArgument, "select a session with the %q metadata", SessionKey)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.sessions[ids[0]]
	if !ok {
		return entry{}, status.Errorf(codes.NotFound, "no session %q", ids[0])
	}
	return e, nil
}

func (h *Hub) infos() []*pb.SessionInfo {
	h.mu.Lock()
	ids := make([]string, 0, len(h.sessions))
	es := map[string]entry{}
	for id, e := range h.sessions {
		ids = append(ids, id)
		es[id] = e
	}
	h.mu.Unlock()
	sort.Strings(ids)
	out := make([]*pb.SessionInfo, 0, len(ids))
	for _, id := range ids {
		info := es[id].sess.Info()
		info.Id = id
		out = append(out, info)
	}
	return out
}

// DialHub connects to the hub at addr (host:port), without transport
// security: see Hub.Serve.
func DialHub(addr string) (*grpc.ClientConn, pb.SessionClient, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connectParams))
	if err != nil {
		return nil, nil, err
	}
	return conn, pb.NewSessionClient(conn), nil
}

// WithSession selects session id on a hub for the calls made with the
// returned context.
func WithSession(ctx context.Context, id string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, SessionKey, id)
}
