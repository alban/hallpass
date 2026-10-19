// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
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

type client struct {
	t      *testing.T
	url    string
	cookie *http.Cookie
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
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
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
	if resp.StatusCode != http.StatusNoContent || len(resp.Cookies()) != 1 {
		t.Fatalf("pair: %s", resp.Status)
	}
	c.cookie = resp.Cookies()[0]
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %v: want HttpOnly, SameSite=Strict", c.cookie)
	}
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
