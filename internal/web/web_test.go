// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

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
	hs := httptest.NewServer(s.Handler())
	t.Cleanup(hs.Close)
	return s, client{t: t, url: hs.URL}, answered
}

func pair(t *testing.T, s *Server, c client) client {
	t.Helper()
	tok := s.NewToken()
	resp := c.do("GET", "/pair?token="+tok, "")
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Fatalf("pair: %s", resp.Status)
	}
	c.cookie = resp.Cookies()[0]
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie %v: want HttpOnly, SameSite=Strict", c.cookie)
	}
	if resp := c.do("GET", "/pair?token="+tok, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("token reused: %s", resp.Status)
	}
	return c
}

func TestPairing(t *testing.T) {
	s, c, _ := setup(t)
	if resp := c.do("GET", "/api/sessions", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unpaired: %s", resp.Status)
	}
	if resp := c.do("GET", "/pair?token=", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("empty token before any: %s", resp.Status)
	}
	s.NewToken()
	if resp := c.do("GET", "/pair?token=bad", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad token: %s", resp.Status)
	}
	c = pair(t, s, c)
	if resp := c.do("GET", "/api/sessions", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("paired: %s", resp.Status)
	}
	if resp := c.do("GET", "/", ""); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Errorf("page: %s %v", resp.Status, resp.Header)
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
