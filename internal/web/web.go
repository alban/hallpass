// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package web serves a browser UI to follow hallpass sessions and answer
// their requests (`hallpass web`). It is a client of the sessions' sockets
// (package sessionapi), or of a Kubernetes node agent (package
// nodeclient), and holds no policy. See docs/devel/web.md.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/alban/hallpass"
	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/nodeclient"
	"github.com/alban/hallpass/internal/sessionapi"
)

//go:embed static
var static embed.FS

// Client is `hallpass web`'s name in monitor.Reason.Client.
const Client = "hallpass web"

const cookieName = "hallpass-web"

// Server is the web UI. Its zero value is not usable: see New.
type Server struct {
	// SocketDir is where the sessions' sockets are.
	SocketDir string

	// A node agent's session API, instead of SocketDir (see NewNode).
	node     pb.SessionClient
	nodeConn *grpc.ClientConn

	cookie string // random per process

	mu       sync.Mutex
	token    string // the pairing token; "" once used
	sessions map[int]*session
}

type session struct {
	conn   *grpc.ClientConn
	client pb.SessionClient
}

// New returns a server for the sessions in sessionapi.SocketDir.
func New() *Server {
	return &Server{
		SocketDir: sessionapi.SocketDir(),
		cookie:    randomHex(32),
		sessions:  map[int]*session{},
	}
}

// NewNode returns a server for the sessions of the Kubernetes node agent
// at addr (host:port), usually a kubectl port-forward to hallpass-node.
// Sessions are then named by their id rather than by pid.
func NewNode(addr string) (*Server, error) {
	conn, c, err := nodeclient.Dial(addr)
	if err != nil {
		return nil, err
	}
	s := New()
	s.node, s.nodeConn = c, conn
	return s, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewToken returns a new one-time pairing token, replacing the previous.
func (s *Server) NewToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = randomHex(16)
	return s.token
}

// Close closes the connections to the sessions.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for pid, c := range s.sessions {
		c.conn.Close()
		delete(s.sessions, pid)
	}
	if s.nodeConn != nil {
		s.nodeConn.Close()
	}
}

// Handler returns the UI's HTTP handler.
func (s *Server) Handler() http.Handler {
	sub, _ := fs.Sub(static, "static")
	files := http.FileServerFS(sub)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pair", s.pair)
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(hallpass.Logo)
	})
	mux.Handle("GET /", s.auth(files.ServeHTTP))
	mux.Handle("GET /api/sessions", s.auth(s.list))
	mux.Handle("GET /api/sessions/{key}/snapshot", s.auth(s.snapshot))
	mux.Handle("GET /api/sessions/{key}/events", s.auth(s.events))
	mux.Handle("POST /api/sessions/{key}/answer", s.auth(s.answer))
	mux.Handle("POST /api/sessions/{key}/rules", s.auth(s.rules))
	return checkOrigin(mux)
}

// loopbackHost reports whether host, a Host header, names this machine
// by its loopback address. Any port: a port forward may change it.
func loopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

// checkOrigin stops DNS rebinding (a foreign Host) and cross-site requests
// (a foreign Origin; browsers send it with every POST).
func checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !loopbackHost(r.Host) {
			http.Error(w, "bad Host", http.StatusForbidden)
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://"+r.Host {
			http.Error(w, "bad Origin", http.StatusForbidden)
			return
		}
		if origin == "" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "missing Origin", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// pair exchanges the one-time token for the session cookie.
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	s.mu.Lock()
	ok := s.token != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) == 1
	if ok {
		s.token = ""
	}
	s.mu.Unlock()
	if !ok {
		http.Error(w, "This pairing link is not valid (it works once). Press Enter in the terminal running hallpass web for a new one.", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.cookie, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(s.cookie)) != 1 {
			http.Error(w, "Not paired: open the link printed by hallpass web.", http.StatusUnauthorized)
			return
		}
		h(w, r)
	})
}

// client returns a client of session pid, connecting if needed.
func (s *Server) client(pid int) (pb.SessionClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.sessions[pid]; ok {
		return c.client, nil
	}
	path := filepath.Join(s.SocketDir, strconv.Itoa(pid)+".sock")
	if _, err := os.Stat(path); err != nil {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	conn, c, err := sessionapi.Dial(path)
	if err != nil {
		return nil, err
	}
	s.sessions[pid] = &session{conn, c}
	return c, nil
}

func (s *Server) drop(pid int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.sessions[pid]; ok {
		c.conn.Close()
		delete(s.sessions, pid)
	}
}

// sessionClient returns a client of the session named by the request's
// key (a pid, or a node agent's session id) and the context selecting it.
func (s *Server) sessionClient(w http.ResponseWriter, r *http.Request) (pb.SessionClient, context.Context, bool) {
	key := r.PathValue("key")
	if s.node != nil {
		return s.node, nodeclient.WithSession(r.Context(), key), true
	}
	pid, err := strconv.Atoi(key)
	if err != nil || pid <= 0 {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return nil, nil, false
	}
	c, err := s.client(pid)
	if err != nil {
		writeError(w, err)
		return nil, nil, false
	}
	return c, r.Context(), true
}

var marshal = protojson.MarshalOptions{}

func writeProto(w http.ResponseWriter, m proto.Message) {
	b, err := marshal.Marshal(m)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func writeError(w http.ResponseWriter, err error) {
	st := status.Convert(err)
	code := http.StatusBadGateway
	switch st.Code() {
	case codes.NotFound:
		code = http.StatusNotFound
	case codes.InvalidArgument:
		code = http.StatusBadRequest
	case codes.FailedPrecondition:
		code = http.StatusConflict
	case codes.PermissionDenied:
		code = http.StatusForbidden
	}
	http.Error(w, st.Message(), code)
}

// list returns the live sessions' Info, oldest first.
func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		start time.Time
		info  json.RawMessage
	}
	var entries []entry
	if s.node != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		reply, err := s.node.List(ctx, &pb.ListRequest{})
		cancel()
		if err != nil {
			writeError(w, err)
			return
		}
		for _, info := range reply.Sessions {
			if b, err := marshal.Marshal(info); err == nil {
				entries = append(entries, entry{info.StartTime.AsTime(), b})
			}
		}
	}
	var paths []string
	if s.node == nil {
		paths, _ = filepath.Glob(filepath.Join(s.SocketDir, "*.sock"))
	}
	for _, p := range paths {
		pid, err := strconv.Atoi(strings.TrimSuffix(filepath.Base(p), ".sock"))
		if err != nil {
			continue
		}
		c, err := s.client(pid)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		info, err := c.Info(ctx, &pb.InfoRequest{})
		cancel()
		if err != nil {
			// A stale socket, or a fake one: forget the connection.
			s.drop(pid)
			continue
		}
		b, err := marshal.Marshal(info)
		if err != nil {
			continue
		}
		entries = append(entries, entry{info.StartTime.AsTime(), b})
	}
	sort.SliceStable(entries, func(a, b int) bool { return entries[a].start.Before(entries[b].start) })
	infos := make([]json.RawMessage, len(entries))
	for i, e := range entries {
		infos[i] = e.info
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(infos)
}

func (s *Server) snapshot(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.sessionClient(w, r)
	if !ok {
		return
	}
	snap, err := c.Snapshot(ctx, &pb.SnapshotRequest{})
	if err != nil {
		writeError(w, err)
		return
	}
	writeProto(w, snap)
}

// heartbeat keeps idle event streams open through proxies.
var heartbeat = 15 * time.Second

// events streams the session's snapshot, then its events, as server-sent
// events: one EventBatch (protojson) per message, and an "end" event when
// the session ends.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.sessionClient(w, r)
	if !ok {
		return
	}
	stream, err := c.Events(ctx, &pb.EventsRequest{Decided: true, Snapshot: true})
	if err != nil {
		writeError(w, err)
		return
	}
	// Wait for the first batch, so that a failure is still an HTTP error.
	first, err := stream.Recv()
	if err != nil {
		writeError(w, err)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	batches := make(chan *pb.EventBatch)
	go func() {
		defer close(batches)
		for {
			b, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case batches <- b:
			case <-r.Context().Done():
				return
			}
		}
	}()
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	for b := first; ; {
		if b != nil {
			data, err := marshal.Marshal(b)
			if err != nil {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
		} else {
			fmt.Fprint(w, ": heartbeat\n\n")
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case nb, ok := <-batches:
			if !ok {
				fmt.Fprint(w, "event: end\ndata: {}\n\n")
				_ = rc.Flush()
				return
			}
			b = nb
		case <-tick.C:
			b = nil
		case <-r.Context().Done():
			return
		}
	}
}

// maxBody bounds request bodies: they are a few fields.
const maxBody = 64 << 10

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// answer answers a request the way the terminal would: once, temp,
// always, deny or never.
func (s *Server) answer(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.sessionClient(w, r)
	if !ok {
		return
	}
	var req struct {
		Request string `json:"request"` // as protojson writes ids
		Answer  string `json:"answer"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := strconv.ParseUint(req.Request, 10, 64)
	if err != nil {
		http.Error(w, "bad request id", http.StatusBadRequest)
		return
	}
	if _, err := c.Answer(ctx, &pb.AnswerRequest{Request: id, Answer: req.Answer, Client: Client}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rules removes rules, by id or by set.
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.sessionClient(w, r)
	if !ok {
		return
	}
	var req struct {
		Remove     []string `json:"remove"` // rule ids, as protojson writes them
		RemoveSets []string `json:"removeSets"`
	}
	if !decode(w, r, &req) {
		return
	}
	d := &pb.Decision{RemoveSets: req.RemoveSets, Client: Client}
	for _, id := range req.Remove {
		n, err := strconv.ParseUint(id, 10, 64)
		if err != nil {
			http.Error(w, "bad rule id", http.StatusBadRequest)
			return
		}
		d.RemoveRules = append(d.RemoveRules, n)
	}
	if len(d.RemoveRules) == 0 && len(d.RemoveSets) == 0 {
		http.Error(w, "nothing to remove", http.StatusBadRequest)
		return
	}
	if _, err := c.Apply(ctx, d); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Listen checks that addr is a loopback address and listens on it.
func Listen(addr string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return nil, errors.New("hallpass web only listens on a loopback address (see docs/devel/web.md#security)")
	}
	return net.Listen("tcp", addr)
}
