// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package web serves a browser UI to follow hallpass sessions and answer
// their requests: `hallpass web` for all sessions, or a session for itself
// (NewSession). It is a client of the sessions' sockets (package
// sessionapi), or of a Kubernetes node agent (package nodeclient), and
// holds no policy. See docs/devel/web.md.
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
	"github.com/alban/hallpass/internal/rulepb"
	"github.com/alban/hallpass/internal/sessionapi"
)

//go:embed static
var static embed.FS

// Client is `hallpass web`'s name in monitor.Reason.Client.
const Client = "hallpass web"

// PairTimeout is how long a pairing waits for the user's confirmation.
const PairTimeout = 60 * time.Second

// Server is the web UI. Its zero value is not usable: see New.
type Server struct {
	// SocketDir is where the sessions' sockets are.
	SocketDir string

	// Confirm asks the user whether to pair the browser showing code
	// ("482 913"), somewhere the sandbox cannot answer: hallpass web's
	// terminal, the session's overlay or a desktop notification. It
	// returns false when ctx ends: the pairing expired, or was cancelled.
	// Without it, browsers cannot pair.
	Confirm func(ctx context.Context, code string) bool
	// Warn, when set, tells the user something they should know, such as a
	// pairing cancelled because another one started meanwhile.
	Warn func(msg string)
	// Watching, when set, is told whether a paired page shows the sessions
	// now: its events stream is connected and the page is visible (not a
	// background tab, nor a minimised window). Called with the server's
	// lock held, on each change: it must not block.
	Watching func(bool)

	// A node agent's session API, instead of SocketDir (see NewNode).
	node     pb.SessionClient
	nodeConn *grpc.ClientConn

	credential  string // random per process; given to paired browsers
	pairTimeout time.Duration

	// only, when set, is the one session served (see NewSession).
	only int

	mu        sync.Mutex
	pairing   *pairing  // the last pairing started, until the browser gets its result
	pairUntil time.Time // with only: pairing is allowed until then (AllowPairing)
	sessions  map[int]*session
	tabs      map[string]*tab // pages following events, by the id they chose
	watching  bool            // last value given to Watching
}

// tab is a page following sessions' events.
type tab struct {
	streams int // open event streams
	visible bool
	seq     uint64 // the page's count of reports, against reordering
}

// pairing is a browser's request to pair. id names it to its browser only;
// code is shown both in the browser and by Confirm.
type pairing struct {
	id, code  string
	cancel    context.CancelCauseFunc
	cancelled bool          // by another pairing; guarded by Server.mu
	done      chan struct{} // closed once decided; ok and err are set then
	ok        bool
	err       error // why not, when !ok
}

var (
	errPairRefused   = errors.New("pairing refused in hallpass")
	errPairExpired   = errors.New("pairing expired: nobody confirmed it in time")
	errPairContended = errors.New("pairing cancelled: something else tried to pair at the same time")
	errPairGone      = errors.New("pairing cancelled: the browser went away")
)

type session struct {
	conn   *grpc.ClientConn
	client pb.SessionClient
}

// New returns a server for the sessions in sessionapi.SocketDir.
func New() *Server {
	return &Server{
		SocketDir:   sessionapi.SocketDir(),
		credential:  randomHex(32),
		pairTimeout: PairTimeout,
		sessions:    map[int]*session{},
		tabs:        map[string]*tab{},
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

// NewSession returns a server for session pid only, which a session embeds
// to open its own web UI: the list shows only it, and other sessions are
// refused. A browser may pair only right after AllowPairing, that is after
// the user asked to open the page, so the sandbox cannot start pairings
// out of the blue.
func NewSession(pid int) *Server {
	s := New()
	s.only = pid
	return s
}

// AllowPairing lets one browser pair within PairTimeout. Only for servers
// from NewSession, which refuse pairing otherwise.
func (s *Server) AllowPairing() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pairUntil = time.Now().Add(s.pairTimeout)
}

// closePairing ends the pairing window AllowPairing opened: a page that got
// the credential from another tab of the same browser (see app.js) does not
// pair, and the window must not stay open to the sandbox.
func (s *Server) closePairing(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.pairUntil = time.Time{}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// scope tells the page, before pairing, what the server serves, for its
// title: one session (its pid, which the sandbox knows anyway), a node's
// sessions, or this user's.
func (s *Server) scope(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Session int  `json:"session,omitempty"`
		Node    bool `json:"node,omitempty"`
	}{s.only, s.node != nil})
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// randomCode returns a pairing code: six random digits, grouped by three.
func randomCode() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	n := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) % 1000000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000)
}

// Close closes the connections to the sessions, and cancels a pending
// pairing.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairing != nil {
		s.pairing.cancel(errors.New("the web UI stopped"))
	}
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
	mux.HandleFunc("POST /api/pair", s.pair)
	mux.HandleFunc("POST /api/pair/wait", s.pairWait)
	mux.HandleFunc("GET /api/scope", s.scope)
	mux.Handle("POST /api/pair/close", s.auth(s.closePairing))
	mux.HandleFunc("GET /favicon.svg", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write(hallpass.Logo)
	})
	// The page holds no secret: it is served before pairing, to pair.
	mux.Handle("GET /", files)
	mux.Handle("GET /api/sessions", s.auth(s.list))
	mux.Handle("GET /api/sessions/{key}/snapshot", s.auth(s.snapshot))
	mux.Handle("GET /api/sessions/{key}/events", s.auth(s.events))
	mux.Handle("POST /api/sessions/{key}/answer", s.auth(s.answer))
	mux.Handle("POST /api/sessions/{key}/rules", s.auth(s.rules))
	mux.Handle("POST /api/visibility", s.auth(s.visibility))
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

// pair starts pairing a browser. It returns the pairing's id, which only
// this browser learns, and its code, which the browser shows and Confirm
// asks about; the browser then waits for the outcome with pairWait. At most
// one pairing is pending: another request cancels both, so that a
// sandboxed process racing the user's browser shows up as a warning
// rather than as a second code to tell apart.
func (s *Server) pair(w http.ResponseWriter, r *http.Request) {
	if s.Confirm == nil {
		http.Error(w, "This server cannot pair browsers.", http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	if old := s.pairing; old != nil && !old.cancelled && !old.decided() {
		old.cancelled = true
		old.cancel(errPairContended)
		s.mu.Unlock()
		s.warn("two browsers tried to pair at once: both pairings cancelled. If you opened only one page, something else tried to pair, maybe the sandbox.")
		http.Error(w, errPairContended.Error(), http.StatusConflict)
		return
	}
	// Checked after the contention above, so that a sandbox racing the
	// user's browser still shows up as a warning.
	if s.only != 0 {
		if time.Now().After(s.pairUntil) {
			s.mu.Unlock()
			http.Error(w, "Not expecting a browser: open the web UI from the session (Ctrl-] then w, or Open web UI in its notification) to pair.", http.StatusForbidden)
			return
		}
		s.pairUntil = time.Time{}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	p := &pairing{id: randomHex(16), code: randomCode(), cancel: cancel, done: make(chan struct{})}
	s.pairing = p
	s.mu.Unlock()
	go func() {
		tctx, tcancel := context.WithTimeoutCause(ctx, s.pairTimeout, errPairExpired)
		defer tcancel()
		ok := s.Confirm(tctx, p.code)
		switch {
		case tctx.Err() != nil:
			p.err = context.Cause(tctx)
		case !ok:
			p.err = errPairRefused
		default:
			p.ok = true
		}
		close(p.done)
		cancel(nil)
		// Forget the outcome if the browser does not come for it.
		time.AfterFunc(s.pairTimeout, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.pairing == p {
				s.pairing = nil
			}
		})
	}()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"id": p.id, "code": p.code})
}

func (p *pairing) decided() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (s *Server) warn(msg string) {
	if s.Warn != nil {
		s.Warn(msg)
	}
}

// pairWait waits for the outcome of the browser's pairing, and gives it
// the credential if the user confirmed it. The browser going away
// cancels the pairing.
func (s *Server) pairWait(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	p := s.pairing
	s.mu.Unlock()
	if p == nil || subtle.ConstantTimeCompare([]byte(req.ID), []byte(p.id)) != 1 {
		http.Error(w, "No such pairing: reload the page to pair again.", http.StatusNotFound)
		return
	}
	select {
	case <-p.done:
	case <-r.Context().Done():
		p.cancel(errPairGone)
		return
	}
	s.mu.Lock()
	if s.pairing == p {
		s.pairing = nil
	}
	s.mu.Unlock()
	if !p.ok {
		http.Error(w, p.err.Error(), http.StatusForbidden)
		return
	}
	reply := map[string]string{"credential": s.credential}
	if s.only != 0 {
		// The page then shows this session only.
		reply["session"] = strconv.Itoa(s.only)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

// auth checks the credential, which the page keeps in memory only and
// sends as "Authorization: Bearer ...". Not a cookie: browsers write
// those to their profile, which the sandbox may read.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.credential)) != 1 {
			http.Error(w, "Not paired: reload the page to pair.", http.StatusUnauthorized)
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
	if s.only != 0 && pid != s.only {
		http.Error(w, "no such session", http.StatusNotFound)
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
	switch {
	case s.only != 0:
		paths = []string{filepath.Join(s.SocketDir, strconv.Itoa(s.only)+".sock")}
	case s.node == nil:
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
	if id := r.URL.Query().Get("tab"); id != "" && len(id) <= 64 {
		visible := r.URL.Query().Get("visible") == "1"
		seq, _ := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
		s.updateTab(id, func(t *tab) {
			t.streams++
			if seq >= t.seq {
				t.visible, t.seq = visible, seq
			}
		})
		defer s.updateTab(id, func(t *tab) { t.streams-- })
	}
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

// updateTab applies f to the page named id, forgets it once it follows no
// events, and tells Watching if a page shows the sessions now.
func (s *Server) updateTab(id string, f func(*tab)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tabs[id]
	if t == nil {
		t = &tab{}
		s.tabs[id] = t
	}
	f(t)
	if t.streams <= 0 {
		delete(s.tabs, id)
	}
	watching := false
	for _, t := range s.tabs {
		watching = watching || t.visible
	}
	if watching != s.watching {
		s.watching = watching
		if s.Watching != nil {
			s.Watching(watching)
		}
	}
}

// visibility records whether a page is watched, from its visibilitychange,
// focus and blur events; its event streams carry the first value. Each
// report is numbered: concurrent requests may arrive out of order.
func (s *Server) visibility(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tab     string `json:"tab"`
		Visible bool   `json:"visible"`
		Seq     uint64 `json:"seq"`
	}
	if !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	_, ok := s.tabs[req.Tab]
	s.mu.Unlock()
	if ok {
		s.updateTab(req.Tab, func(t *tab) {
			if req.Seq > t.seq {
				t.visible, t.seq = req.Visible, req.Seq
			}
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

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
// always, group, deny or never; grant or deny for a request made in advance.
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

// rules changes the session's rules in one decision: it removes rules, by
// id or by set, and adds rules written in the rules.SpecSyntax. With
// ifGeneration, it fails with 409 if the rules changed since that snapshot.
func (s *Server) rules(w http.ResponseWriter, r *http.Request) {
	c, ctx, ok := s.sessionClient(w, r)
	if !ok {
		return
	}
	var req struct {
		Remove       []string `json:"remove"` // rule ids, as protojson writes them
		RemoveSets   []string `json:"removeSets"`
		Add          []string `json:"add"`
		Label        string   `json:"label"` // of the added rules
		IfGeneration string   `json:"ifGeneration"`
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
	if req.IfGeneration != "" {
		n, err := strconv.ParseUint(req.IfGeneration, 10, 64)
		if err != nil {
			http.Error(w, "bad generation", http.StatusBadRequest)
			return
		}
		d.IfGeneration = n
	}
	add, err := rulepb.Parse(req.Add, req.Label, time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	d.AddRules = add
	if len(d.RemoveRules) == 0 && len(d.RemoveSets) == 0 && len(d.AddRules) == 0 {
		http.Error(w, "nothing to change", http.StatusBadRequest)
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
