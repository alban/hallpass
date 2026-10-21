// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/answer"
	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionapi"
)

type fakeSession struct{ answered chan string }

func (fakeSession) Info() *pb.SessionInfo {
	return &pb.SessionInfo{Pid: int32(os.Getpid()), Mode: "lite"}
}
func (fakeSession) Prompt(*monitor.Request) *pb.Prompt { return &pb.Prompt{} }
func (f fakeSession) Answer(id uint64, answer, client string) error {
	f.answered <- strconv.FormatUint(id, 10) + " " + answer + " " + client
	return nil
}
func (fakeSession) CheckRules(_ string, add, removed []rules.Rule) error {
	return answer.CheckRules(defaults.New("/home/u", "", nil, nil), add, removed)
}
func (fakeSession) RulesChanged(string, []rules.Rule, []rules.Rule) {}

type client struct {
	t       *testing.T
	url     string
	cred    string
	session string // the one session followed, if the server says so
}

func (c client) do(method, path, body string, hdr ...string) *http.Response {
	c.t.Helper()
	req, err := http.NewRequest(method, c.url+path, strings.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", c.url)
	}
	if c.cred != "" {
		req.Header.Set("Authorization", "Bearer "+c.cred)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	c.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func setup(t *testing.T) (*Server, client, chan string) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	answered := make(chan string, 1)
	sess, err := sessionapi.Listen(m, fakeSession{answered})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	s := New()
	t.Cleanup(s.Close)
	return s, serve(t, s), answered
}

func serve(t *testing.T, s *Server) client {
	t.Helper()
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	return client{t: t, url: hs.URL}
}

// user confirms pairings as the test tells it: Confirm sends each code to
// codes, and returns the next value of answers.
type user struct {
	codes   chan string
	answers chan bool
}

func newUser(s *Server) user {
	u := user{codes: make(chan string, 4), answers: make(chan bool, 4)}
	s.Confirm = func(ctx context.Context, code string) bool {
		u.codes <- code
		select {
		case a := <-u.answers:
			return a
		case <-ctx.Done():
			return false
		}
	}
	return u
}

// startPair starts pairing, and returns the pairing's id and code.
func startPair(t *testing.T, c client) (id, code string) {
	t.Helper()
	resp := c.do("POST", "/api/pair", "")
	var p struct{ ID, Code string }
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("pair: %s %v", resp.Status, err)
	}
	return p.ID, p.Code
}

func pair(t *testing.T, s *Server, c client) client {
	t.Helper()
	u := newUser(s)
	id, code := startPair(t, c)
	if got := <-u.codes; got != code {
		t.Errorf("confirm %q, browser shows %q", got, code)
	}
	if ok, _ := regexp.MatchString(`^\d{3} \d{3}$`, code); !ok {
		t.Errorf("code %q", code)
	}
	u.answers <- true
	resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`)
	var paired struct{ Credential, Session string }
	if err := json.NewDecoder(resp.Body).Decode(&paired); err != nil || resp.StatusCode != http.StatusOK || len(paired.Credential) < 32 {
		t.Fatalf("pair: %s %v", resp.Status, err)
	}
	if len(resp.Cookies()) != 0 {
		t.Errorf("cookies %v: the credential must stay in the page's memory", resp.Cookies())
	}
	c.cred, c.session = paired.Credential, paired.Session
	if resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("pairing reused: %s", resp.Status)
	}
	return c
}

func TestPairing(t *testing.T) {
	s, c, _ := setup(t)
	if resp := c.do("GET", "/api/sessions", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unpaired: %s", resp.Status)
	}
	if resp := c.do("GET", "/", ""); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("page: %s %v", resp.Status, resp.Header)
	}
	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("pair without Confirm: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/pair/wait", `{"id":"nope"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("no pairing: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/pair", "", "Origin", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("pair without Origin: %s", resp.Status)
	}

	u := newUser(s)
	id, _ := startPair(t, c)
	<-u.codes
	if resp := c.do("POST", "/api/pair/wait", `{"id":"bad"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bad id: %s", resp.Status)
	}
	u.answers <- false
	resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`)
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 || !strings.Contains(string(body), "refused") {
		t.Errorf("refused: %s %s", resp.Status, body)
	}

	c = pair(t, s, c)
	if resp := c.do("GET", "/api/sessions", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("paired: %s", resp.Status)
	}
	bad := c
	bad.cred = strings.Repeat("0", len(c.cred))
	if resp := bad.do("GET", "/api/sessions", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad credential: %s", resp.Status)
	}
	if resp := c.do("GET", "/api/sessions", "", "Authorization", c.cred); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("credential without Bearer: %s", resp.Status)
	}
	if New().credential == s.credential {
		t.Error("same credential in two servers")
	}
}

// TestPairingContended checks that a second pairing cancels both, with a
// warning: the user cannot confirm the wrong one.
func TestPairingContended(t *testing.T) {
	s, c, _ := setup(t)
	warned := make(chan string, 1)
	s.Warn = func(msg string) { warned <- msg }
	u := newUser(s)
	id, _ := startPair(t, c)
	<-u.codes
	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("second pairing: %s", resp.Status)
	}
	if msg := <-warned; !strings.Contains(msg, "something else tried to pair") {
		t.Errorf("warning %q", msg)
	}
	resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`)
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "something else") {
		t.Errorf("first pairing: %s %s", resp.Status, body)
	}
	// The next one goes through.
	pair(t, s, c)
}

func TestPairingExpires(t *testing.T) {
	s, c, _ := setup(t)
	s.pairTimeout = 100 * time.Millisecond
	u := newUser(s)
	id, _ := startPair(t, c)
	<-u.codes
	resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`)
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "expired") {
		t.Errorf("expired: %s %s", resp.Status, body)
	}
}

// TestPairingBrowserGone checks that the browser going away takes the
// question down.
func TestPairingBrowserGone(t *testing.T) {
	s, c, _ := setup(t)
	gone := make(chan error, 1)
	s.Confirm = func(ctx context.Context, code string) bool {
		<-ctx.Done()
		gone <- context.Cause(ctx)
		return false
	}
	id, _ := startPair(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", c.url+"/api/pair/wait", strings.NewReader(`{"id":"`+id+`"}`))
	req.Header.Set("Origin", c.url)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("wait: %s", resp.Status)
	}
	select {
	case err := <-gone:
		if !errors.Is(err, errPairGone) {
			t.Errorf("cause %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm still asking")
	}
}

func TestHostOrigin(t *testing.T) {
	s, c, _ := setup(t)
	c = pair(t, s, c)
	pid := strconv.Itoa(os.Getpid())
	for _, tc := range []struct {
		name, method string
		hdr          []string
		want         int
	}{
		{"rebinding", "GET", []string{"Host", "evil.example:80"}, http.StatusForbidden},
		{"localhost", "GET", []string{"Host", "localhost:1234"}, http.StatusOK},
		{"cross-site GET", "GET", []string{"Origin", "http://evil.example"}, http.StatusForbidden},
		{"cross-site POST", "POST", []string{"Origin", "http://evil.example"}, http.StatusForbidden},
		{"POST without Origin", "POST", []string{"Origin", ""}, http.StatusForbidden},
	} {
		path := "/api/sessions"
		if tc.method == "POST" {
			path = "/api/sessions/" + pid + "/answer"
		}
		if resp := c.do(tc.method, path, `{"request":"1","answer":"once"}`, tc.hdr...); resp.StatusCode != tc.want {
			t.Errorf("%s: %s, want %d", tc.name, resp.Status, tc.want)
		}
	}
}

func TestAPI(t *testing.T) {
	s, c, answered := setup(t)
	c = pair(t, s, c)
	pid := strconv.Itoa(os.Getpid())

	resp := c.do("GET", "/api/sessions", "")
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"pid":`+pid) {
		t.Errorf("sessions: %s", body)
	}

	resp = c.do("GET", "/api/sessions/"+pid+"/events", "")
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("events: %s %s", resp.Status, ct)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "data: ") || !strings.Contains(line, `"snapshot"`) {
		t.Errorf("first event %q: %v", line, err)
	}

	resp = c.do("POST", "/api/sessions/"+pid+"/answer", `{"request":"7","answer":"temp"}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("answer: %s", resp.Status)
	}
	if got := <-answered; got != "7 temp "+Client {
		t.Errorf("answered %q", got)
	}
	if resp := c.do("POST", "/api/sessions/"+pid+"/answer", `{"request":"7","answer":"once","extra":1}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field: %s", resp.Status)
	}
	if resp := c.do("GET", "/api/sessions/1/events", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("no such session: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/sessions/"+pid+"/rules", `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty rules change: %s", resp.Status)
	}
	if c.session != "" {
		t.Errorf("hallpass web follows session %q only", c.session)
	}
}

// TestRules edits a session's rules the way the Rules tab does.
func TestRules(t *testing.T) {
	s, c, _ := setup(t)
	c = pair(t, s, c)
	url := "/api/sessions/" + strconv.Itoa(os.Getpid()) + "/rules"
	snapshot := func() (gen string, ids map[string]string) {
		t.Helper()
		resp := c.do("GET", "/api/sessions/"+strconv.Itoa(os.Getpid())+"/snapshot", "")
		var snap struct {
			Generation string
			Rules      []json.RawMessage
		}
		if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
			t.Fatal(err)
		}
		ids = map[string]string{}
		for _, raw := range snap.Rules {
			var r pb.Rule
			if err := protojson.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			ids[r.GetSpec()+" "+r.GetLabel()] = strconv.FormatUint(r.GetId(), 10)
		}
		return snap.Generation, ids
	}
	post := func(body string, want int) {
		t.Helper()
		resp := c.do("POST", url, body)
		if resp.StatusCode != want {
			msg, _ := io.ReadAll(resp.Body)
			t.Errorf("%s: %s %s, want %d", body, resp.Status, msg, want)
		}
	}

	post(`{"add":["deny write /home/u/x"],"label":"mine"}`, http.StatusNoContent)
	gen, ids := snapshot()
	id := ids["deny write /home/u/x mine"]
	if id == "" {
		t.Fatalf("rules %v", ids)
	}
	edit := `{"remove":["` + id + `"],"add":["deny write /home/u/y"],"label":"mine","ifGeneration":"` + gen + `"}`
	post(edit, http.StatusNoContent)
	if _, ids := snapshot(); ids["deny write /home/u/y mine"] == "" || ids["deny write /home/u/x mine"] != "" {
		t.Errorf("after the edit: %v", ids)
	}
	post(edit, http.StatusConflict)
	post(`{"add":["allow write /home/u/**"]}`, http.StatusForbidden)
	post(`{"add":["allow write /home/u/src/f for 1h"]}`, http.StatusNoContent)
	post(`{"add":["allow write relative"]}`, http.StatusBadRequest)
	post(`{"ifGeneration":"x","add":["deny write /a"]}`, http.StatusBadRequest)
}

// TestWatching: a page tells whether it shows the sessions, connected and
// visible, so that a session's desktop notifications can give way to it.
func TestWatching(t *testing.T) {
	s, c, _ := setup(t)
	c = pair(t, s, c)
	pid := strconv.Itoa(os.Getpid())
	watching := make(chan bool, 8)
	s.mu.Lock()
	s.Watching = func(w bool) { watching <- w }
	s.mu.Unlock()
	expect := func(want bool) {
		t.Helper()
		select {
		case got := <-watching:
			if got != want {
				t.Errorf("watching %v, want %v", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("watching: no change to %v", want)
		}
	}
	none := func() {
		t.Helper()
		select {
		case got := <-watching:
			t.Errorf("watching %v, want no change", got)
		case <-time.After(100 * time.Millisecond):
		}
	}
	follow := func(tab, visible string) *http.Response {
		t.Helper()
		resp := c.do("GET", "/api/sessions/"+pid+"/events?tab="+tab+"&visible="+visible, "")
		if _, err := bufio.NewReader(resp.Body).ReadString('\n'); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	post := func(tab string, visible bool, seq int) {
		t.Helper()
		body := fmt.Sprintf(`{"tab":%q,"visible":%v,"seq":%d}`, tab, visible, seq)
		if resp := c.do("POST", "/api/visibility", body); resp.StatusCode != http.StatusNoContent {
			t.Fatalf("visibility: %s", resp.Status)
		}
	}
	seq := map[string]int{}
	visibility := func(tab string, visible bool) {
		t.Helper()
		seq[tab]++
		post(tab, visible, seq[tab])
	}

	hiddenTab := follow("a", "0")
	none()
	visibility("a", true)
	expect(true)
	other := follow("b", "1")
	visibility("a", false)
	none() // b shows them still
	other.Body.Close()
	expect(false)
	visibility("b", true) // gone: no effect
	none()
	visibility("a", true)
	expect(true)
	post("a", false, seq["a"]-1) // an older report, arriving late
	none()
	hiddenTab.Body.Close()
	expect(false)
	if resp := (client{t: t, url: c.url}).do("POST", "/api/visibility", `{"tab":"a","visible":true}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("visibility without credential: %s", resp.Status)
	}
}

// TestSession checks the server a session embeds: its own session only,
// and pairing only after the user opened the page.
func TestSession(t *testing.T) {
	setup(t)
	pid := strconv.Itoa(os.Getpid())
	s := NewSession(os.Getpid())
	t.Cleanup(s.Close)
	warned := make(chan string, 4)
	s.Warn = func(msg string) { warned <- msg }
	c := serve(t, s)
	newUser(s)

	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("pairing before AllowPairing: %s", resp.Status)
	}
	s.AllowPairing()
	c = pair(t, s, c)
	if c.session != pid {
		t.Errorf("session %q, want %s", c.session, pid)
	}
	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("second pairing with one AllowPairing: %s", resp.Status)
	}
	// A tab that borrowed the credential closes the pairing window.
	s.AllowPairing()
	if resp := (client{t: t, url: c.url}).do("POST", "/api/pair/close", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("close pairing without credential: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/pair/close", ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("close pairing: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("pairing after /api/pair/close: %s", resp.Status)
	}
	scope := func(url string) string {
		t.Helper()
		resp := (client{t: t, url: url}).do("GET", "/api/scope", "")
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b))
	}
	if got := scope(c.url); got != `{"session":`+pid+`}` {
		t.Errorf("session scope %s", got)
	}
	if got := scope(serve(t, New()).url); got != `{}` {
		t.Errorf("hallpass web scope %s", got)
	}

	resp := c.do("GET", "/api/sessions", "")
	var infos []struct{ Pid int }
	if err := json.NewDecoder(resp.Body).Decode(&infos); err != nil || len(infos) != 1 || strconv.Itoa(infos[0].Pid) != pid {
		t.Errorf("sessions: %v %v", infos, err)
	}
	for _, path := range []string{"/api/sessions/1/snapshot", "/api/sessions/1/events"} {
		if resp := c.do("GET", path, ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %s", path, resp.Status)
		}
	}
	if resp := c.do("POST", "/api/sessions/1/answer", `{"request":"7","answer":"once"}`); resp.StatusCode != http.StatusNotFound {
		t.Errorf("answer another session: %s", resp.Status)
	}
	if resp := c.do("GET", "/api/sessions/"+pid+"/snapshot", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("own snapshot: %s", resp.Status)
	}

	// Another pairing racing the user's still cancels both, even though
	// pairing is not allowed any more.
	s.AllowPairing()
	newUser(s)
	id, _ := startPair(t, c)
	if resp := c.do("POST", "/api/pair", ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("racing pairing: %s", resp.Status)
	}
	if resp := c.do("POST", "/api/pair/wait", `{"id":"`+id+`"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("raced pairing: %s", resp.Status)
	}
	select {
	case <-warned:
	case <-time.After(5 * time.Second):
		t.Error("no warning")
	}
}

func TestNode(t *testing.T) {
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	answered := make(chan string, 1)
	node := sessionapi.NewNode()
	node.Add("c0ffee", m, fakeSession{answered})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = node.Serve(ln) }()
	t.Cleanup(node.Stop)

	s, err := NewNode(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	c := pair(t, s, client{t: t, url: hs.URL})

	resp := c.do("GET", "/api/sessions", "")
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"id":"c0ffee"`) {
		t.Errorf("sessions: %s %s", resp.Status, body)
	}
	resp = c.do("POST", "/api/sessions/c0ffee/answer", `{"request":"3","answer":"deny"}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("answer: %s", resp.Status)
	}
	if got := <-answered; got != "3 deny "+Client {
		t.Errorf("answered %q", got)
	}
	if resp := c.do("GET", "/api/sessions/nope/snapshot", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("no such session: %s", resp.Status)
	}
}

func TestListenLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "[::]:0"} {
		if ln, err := Listen(addr); err == nil {
			ln.Close()
			t.Errorf("Listen(%q) succeeded", addr)
		}
	}
	ln, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}
