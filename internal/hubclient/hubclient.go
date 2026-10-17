// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package hubclient is a client of the node agent's session API (a
// sessionapi.Hub). It has no system dependency, so it also builds for
// GOOS=js (the Headlamp plugin's wasm client, cmd/headlamp-wasm).
package hubclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "github.com/alban/hallpass/internal/sessionpb"
)

// SessionKey is the gRPC metadata that selects a session on a hub.
const SessionKey = "hallpass-session"

var connectParams = grpc.ConnectParams{
	Backoff:           backoff.Config{BaseDelay: 50 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: time.Second},
	MinConnectTimeout: 5 * time.Second,
}

// Dial connects to the hub at addr (host:port), without transport
// security: the hub listens on its pod's loopback, reached through a
// port-forward.
func Dial(addr string) (*grpc.ClientConn, pb.SessionClient, error) {
	return dial(addr)
}

func dial(target string, opts ...grpc.DialOption) (*grpc.ClientConn, pb.SessionClient, error) {
	opts = append(opts,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connectParams))
	conn, err := grpc.NewClient(target, opts...)
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

// Name is a session's namespace/pod/container.
func Name(s *pb.SessionInfo) string {
	return s.Labels["namespace"] + "/" + s.Labels["pod"] + "/" + s.Labels["container"]
}

// Find resolves ref, a session id, a unique id prefix, or
// namespace/pod/container (the latest session of that container).
func Find(ctx context.Context, c pb.SessionClient, ref string) (string, error) {
	l, err := c.List(ctx, &pb.ListRequest{})
	if err != nil {
		return "", err
	}
	var found *pb.SessionInfo
	n := 0
	for _, s := range l.Sessions {
		switch {
		case s.Id == ref:
			return s.Id, nil
		case strings.Count(ref, "/") == 2 && Name(s) == ref:
			if found == nil || s.StartTime.AsTime().After(found.StartTime.AsTime()) {
				found = s
			}
			n = 1
		case strings.HasPrefix(s.Id, ref):
			found = s
			n++
		}
	}
	switch n {
	case 0:
		return "", fmt.Errorf("no session %q", ref)
	case 1:
		return found.Id, nil
	}
	return "", fmt.Errorf("session %q is ambiguous", ref)
}
