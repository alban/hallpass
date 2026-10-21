// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package nodeclient

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/alban/hallpass/api/session/v1"
)

// fakeNode serves List, Events and Snapshot for the sessions in infos; the
// events of session id are read from events[id].
type fakeNode struct {
	pb.UnimplementedSessionServer

	mu     sync.Mutex
	infos  []*pb.SessionInfo
	events map[string]chan *pb.Event
	rules  []*pb.Rule
}

func (h *fakeNode) List(context.Context, *pb.ListRequest) (*pb.ListReply, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return &pb.ListReply{Sessions: h.infos}, nil
}

func (h *fakeNode) Snapshot(context.Context, *pb.SnapshotRequest) (*pb.SnapshotReply, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return &pb.SnapshotReply{Rules: h.rules, Generation: 2}, nil
}

func (h *fakeNode) Events(_ *pb.EventsRequest, stream grpc.ServerStreamingServer[pb.EventBatch]) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	id := md.Get(SessionKey)[0]
	h.mu.Lock()
	ch := h.events[id]
	h.mu.Unlock()
	snap := &pb.SnapshotReply{Pending: []*pb.Request{{Id: 1, Prompt: &pb.Prompt{Path: "/etc/" + id}}}}
	if err := stream.Send(&pb.EventBatch{Snapshot: snap}); err != nil {
		return err
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&pb.EventBatch{Events: []*pb.Event{e}}); err != nil {
				return err
			}
		}
	}
}

func serveFake(t *testing.T, h *fakeNode) (*grpc.Server, pb.SessionClient) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterSessionServer(srv, h)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, c, err := Dial(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return srv, c
}

// summary is a state as session id -> pending paths.
func summary(st State) map[string][]string {
	out := map[string][]string{}
	for _, s := range st.Sessions {
		paths := []string{}
		for _, r := range s.Pending {
			paths = append(paths, r.GetPrompt().GetPath())
		}
		out[s.Info.Id] = paths
	}
	return out
}

func TestWatch(t *testing.T) {
	h := &fakeNode{
		infos:  []*pb.SessionInfo{{Id: "a"}, {Id: "b"}},
		events: map[string]chan *pb.Event{"a": make(chan *pb.Event), "b": make(chan *pb.Event)},
	}
	srv, c := serveFake(t, h)
	states := make(chan State, 100)
	errc := make(chan error, 1)
	go func() {
		errc <- Watch(context.Background(), c, 20*time.Millisecond, func(st State) { states <- st })
	}()

	// wait returns the first state for which ok holds.
	wait := func(what string, ok func(map[string][]string) bool) State {
		t.Helper()
		timeout := time.After(5 * time.Second)
		for {
			select {
			case st := <-states:
				if ok(summary(st)) {
					return st
				}
			case <-timeout:
				t.Fatalf("timeout waiting for %s", what)
			}
		}
	}
	wait("the snapshots", func(m map[string][]string) bool {
		return len(m) == 2 && len(m["a"]) == 1 && len(m["b"]) == 1
	})

	h.events["a"] <- &pb.Event{Kind: &pb.Event_Opened{Opened: &pb.Request{Id: 2, Prompt: &pb.Prompt{Path: "/x"}}}}
	h.events["a"] <- &pb.Event{Kind: &pb.Event_Closed{Closed: &pb.Closed{Id: 1}}}
	wait("the events", func(m map[string][]string) bool {
		return len(m["a"]) == 1 && m["a"][0] == "/x"
	})

	h.mu.Lock()
	h.rules = []*pb.Rule{{Id: 7, Label: "r", Spec: "allow write /w/**"}}
	h.mu.Unlock()
	h.events["b"] <- &pb.Event{Kind: &pb.Event_Rules{Rules: 2}}
	st := wait("the rules", func(map[string][]string) bool { return true })
	for len(st.Sessions) < 2 || len(st.Sessions[1].Rules) == 0 {
		st = wait("the rules", func(map[string][]string) bool { return true })
	}
	if st.Sessions[1].Rules[0].Id != 7 || st.Sessions[1].Generation != 2 {
		t.Errorf("rules of b: %v generation %d", st.Sessions[1].Rules, st.Sessions[1].Generation)
	}
	if b, _ := json.Marshal(st); !strings.Contains(string(b), `"generation":"2"`) || !strings.Contains(string(b), `"spec":"allow write /w/**"`) {
		t.Errorf("JSON without the generation or the rule's spec: %s", b)
	}

	h.mu.Lock()
	h.infos = h.infos[:1]
	h.mu.Unlock()
	st = wait("b to be gone", func(m map[string][]string) bool { return len(m) == 1 })

	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var js struct {
		Sessions []struct {
			Info    struct{ ID string }
			Pending []struct {
				ID     string
				Prompt struct{ Path string }
			}
		}
	}
	if err := json.Unmarshal(b, &js); err != nil {
		t.Fatal(err)
	}
	if len(js.Sessions) != 1 || js.Sessions[0].Info.ID != "a" || js.Sessions[0].Pending[0].ID != "2" ||
		js.Sessions[0].Pending[0].Prompt.Path != "/x" {
		t.Errorf("JSON: %s", b)
	}

	srv.Stop()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("Watch returned nil after the server stopped")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Watch did not return after the server stopped")
	}
}
