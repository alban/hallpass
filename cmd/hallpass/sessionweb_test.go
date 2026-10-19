// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTerminalMenuOpenWeb opens the session's web UI from the Ctrl-] menu,
// pairs a browser by confirming its code in the overlay, and checks the
// page follows this session only.
func TestTerminalMenuOpenWeb(t *testing.T) {
	e := newEnv(t)
	// A fake xdg-open, which writes down the URL it was asked to open.
	bin := e.root + "/bin"
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	opened := e.root + "/opened"
	if err := os.WriteFile(bin+"/xdg-open", []byte("#!/bin/sh\necho \"$1\" > "+opened+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))

	m, scr, c, done := runTerm(t, e, `echo ready; exec sleep 60`)
	t.Cleanup(func() { _ = c.Process.Kill() })
	waitFor(t, func() bool { return strings.Contains(scr.text(), "ready") }, "the command")
	m.Write([]byte{0x1d})
	waitFor(t, func() bool { return strings.Contains(scr.text(), "[w] open the web UI") }, "menu")
	m.Write([]byte("w"))
	var u string
	waitFor(t, func() bool {
		b, _ := os.ReadFile(opened)
		u = strings.TrimSpace(string(b))
		return strings.HasSuffix(u, "/")
	}, "xdg-open")
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		t.Fatalf("opened %q", u)
	}
	waitFor(t, func() bool { return strings.Contains(scr.text(), "web UI at "+u) }, "notice")

	origin := strings.TrimSuffix(u, "/")
	do := func(method, path, body, cred string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, origin+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		if cred != "" {
			req.Header.Set("Authorization", "Bearer "+cred)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	var p struct{ ID, Code string }
	if resp := do("POST", "/api/pair", "", ""); json.NewDecoder(resp.Body).Decode(&p) != nil || p.Code == "" {
		t.Fatalf("pair: %s", resp.Status)
	}
	waitFor(t, func() bool { return strings.Contains(scr.text(), "pair the browser showing "+p.Code+"?") }, "pairing prompt")
	time.Sleep(700 * time.Millisecond) // past the type-ahead guard
	m.Write([]byte("y"))
	var paired struct{ Credential, Session string }
	if resp := do("POST", "/api/pair/wait", `{"id":"`+p.ID+`"}`, ""); json.NewDecoder(resp.Body).Decode(&paired) != nil {
		t.Fatalf("pair/wait: %s", resp.Status)
	}
	pid := strconv.Itoa(c.Process.Pid)
	if paired.Session != pid || paired.Credential == "" {
		t.Errorf("paired %+v, want session %s", paired, pid)
	}
	resp := do("GET", "/api/sessions", "", paired.Credential)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"pid":`+pid) {
		t.Errorf("sessions: %s %s", resp.Status, body)
	}
	// Opening the page once lets one browser pair.
	if resp := do("POST", "/api/pair", "", ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("second pairing: %s", resp.Status)
	}

	_ = c.Process.Signal(syscall.SIGTERM)
	_ = c.Wait()
	<-done
	if t.Failed() {
		t.Logf("screen:\n%s", scr.text())
	}
}
