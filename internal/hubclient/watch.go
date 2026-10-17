// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package hubclient

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/alban/hallpass/internal/sessionpb"
)

// Session is what a Watcher knows of a session.
type Session struct {
	Info    *pb.SessionInfo
	Pending []*pb.Request // by id
	Rules   []*pb.Rule
}

// State is every session of a hub, by id.
type State struct {
	Sessions []Session
}

// Watch follows every session of the hub behind c: it lists the sessions
// every interval, follows the events of each, and calls onChange with the
// new state after each change, from one goroutine. It returns when ctx is
// done or List fails, e.g. when the connection is lost.
func Watch(ctx context.Context, c pb.SessionClient, interval time.Duration, onChange func(State)) error {
	ctx, cancel := context.WithCancel(ctx)
	w := &watcher{c: c, sessions: map[string]*watched{}, changed: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.changed:
				onChange(w.state())
			}
		}
	}()
	defer func() {
		cancel()
		<-done
	}()
	t := time.NewTicker(interval)
	defer t.Stop()
	first := true
	for {
		l, err := c.List(ctx, &pb.ListRequest{})
		if err != nil {
			return err
		}
		if w.sync(ctx, l.Sessions) || first {
			w.notify()
		}
		first = false
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

type watcher struct {
	c       pb.SessionClient
	changed chan struct{}

	mu       sync.Mutex
	sessions map[string]*watched
}

type watched struct {
	info    *pb.SessionInfo
	pending map[uint64]*pb.Request
	rules   []*pb.Rule
	cancel  context.CancelFunc
}

func (w *watcher) notify() {
	select {
	case w.changed <- struct{}{}:
	default:
	}
}

// sync starts following the listed sessions not followed yet, and drops
// the others. It reports whether the sessions changed.
func (w *watcher) sync(ctx context.Context, infos []*pb.SessionInfo) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := false
	listed := map[string]bool{}
	for _, info := range infos {
		listed[info.Id] = true
		if s, ok := w.sessions[info.Id]; ok {
			if !proto.Equal(s.info, info) {
				s.info = info
				changed = true
			}
			continue
		}
		sctx, cancel := context.WithCancel(WithSession(ctx, info.Id))
		s := &watched{info: info, pending: map[uint64]*pb.Request{}, cancel: cancel}
		w.sessions[info.Id] = s
		go w.follow(sctx, info.Id, s)
		changed = true
	}
	for id, s := range w.sessions {
		if !listed[id] {
			s.cancel()
			delete(w.sessions, id)
			changed = true
		}
	}
	return changed
}

// follow follows a session's events until they end; the session is then
// dropped until the next List names it again.
func (w *watcher) follow(ctx context.Context, id string, s *watched) {
	defer func() {
		s.cancel()
		w.mu.Lock()
		if w.sessions[id] == s {
			delete(w.sessions, id)
		}
		w.mu.Unlock()
		w.notify()
	}()
	stream, err := w.c.Events(ctx, &pb.EventsRequest{Snapshot: true})
	if err != nil {
		return
	}
	for {
		b, err := stream.Recv()
		if err != nil {
			return
		}
		rulesChanged := false
		w.mu.Lock()
		if snap := b.GetSnapshot(); snap != nil {
			s.pending = map[uint64]*pb.Request{}
			for _, r := range snap.Pending {
				s.pending[r.Id] = r
			}
			s.rules = snap.Rules
		}
		for _, e := range b.Events {
			switch k := e.Kind.(type) {
			case *pb.Event_Opened:
				s.pending[k.Opened.Id] = k.Opened
			case *pb.Event_Closed:
				delete(s.pending, k.Closed.Id)
			case *pb.Event_Rules:
				rulesChanged = true
			}
		}
		w.mu.Unlock()
		if rulesChanged {
			if snap, err := w.c.Snapshot(ctx, &pb.SnapshotRequest{}); err == nil {
				w.mu.Lock()
				s.rules = snap.Rules
				w.mu.Unlock()
			}
		}
		w.notify()
	}
}

func (w *watcher) state() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	var st State
	for _, s := range w.sessions {
		out := Session{Info: s.info, Rules: s.rules}
		for _, r := range s.pending {
			out.Pending = append(out.Pending, r)
		}
		sort.Slice(out.Pending, func(i, j int) bool { return out.Pending[i].Id < out.Pending[j].Id })
		st.Sessions = append(st.Sessions, out)
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].Info.Id < st.Sessions[j].Info.Id })
	return st
}

// MarshalJSON writes the state for the plugin: the messages as protojson
// (lowerCamelCase fields, 64-bit integers as strings).
func (st State) MarshalJSON() ([]byte, error) {
	type session struct {
		Info    json.RawMessage   `json:"info"`
		Pending []json.RawMessage `json:"pending"`
		Rules   []json.RawMessage `json:"rules"`
	}
	out := struct {
		Sessions []session `json:"sessions"`
	}{Sessions: []session{}}
	for _, s := range st.Sessions {
		js := session{Pending: []json.RawMessage{}, Rules: []json.RawMessage{}}
		var err error
		if js.Info, err = marshal(s.Info); err != nil {
			return nil, err
		}
		for _, r := range s.Pending {
			b, err := marshal(r)
			if err != nil {
				return nil, err
			}
			js.Pending = append(js.Pending, b)
		}
		for _, r := range s.Rules {
			b, err := marshal(r)
			if err != nil {
				return nil, err
			}
			js.Rules = append(js.Rules, b)
		}
		out.Sessions = append(out.Sessions, js)
	}
	return json.Marshal(out)
}

func marshal(m proto.Message) (json.RawMessage, error) {
	return protojson.Marshal(m)
}
