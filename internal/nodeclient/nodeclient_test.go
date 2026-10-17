// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package nodeclient

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/alban/hallpass/api/session/v1"
)

// lister is a SessionClient serving only List.
type lister struct {
	pb.SessionClient
	sessions []*pb.SessionInfo
}

func (l lister) List(context.Context, *pb.ListRequest, ...grpc.CallOption) (*pb.ListReply, error) {
	return &pb.ListReply{Sessions: l.sessions}, nil
}

func info(id, ns, pod, container string, start int64) *pb.SessionInfo {
	return &pb.SessionInfo{
		Id:        id,
		Labels:    map[string]string{"namespace": ns, "pod": pod, "container": container},
		StartTime: timestamppb.New(time.Unix(start, 0)),
	}
}

func TestFind(t *testing.T) {
	c := lister{sessions: []*pb.SessionInfo{
		info("abc1", "ns", "p", "c", 1),
		info("abc2", "ns", "p", "c", 2),
		info("def", "ns", "q", "c", 1),
	}}
	for _, tt := range []struct{ ref, want string }{
		{"abc1", "abc1"},
		{"de", "def"},
		{"ns/p/c", "abc2"},
		{"ns/q/c", "def"},
		{"abc", ""},
		{"ns/x/c", ""},
	} {
		got, err := Find(context.Background(), c, tt.ref)
		if got != tt.want || (err == nil) != (tt.want != "") {
			t.Errorf("Find(%q) = %q, %v; want %q", tt.ref, got, err, tt.want)
		}
	}
}
