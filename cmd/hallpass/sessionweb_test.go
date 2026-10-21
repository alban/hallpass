// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/sessionapi"
)

// TestTerminalMenuOpenWeb opens the session's web UI from the Ctrl-] menu,
// pairs a browser by confirming its code in the overlay, and checks the
// page follows this session only.
func TestTerminalMenuOpenWeb(t *testing.T) {
	e := newEnv(t)
	opened := fakeXDGOpen(t, e)

	m, scr, c, done := runTerm(t, e, `echo ready; exec sleep 60`)
	t.Cleanup(func() { _ = c.Process.Kill() })
	waitFor(t, func() bool { return strings.Contains(scr.text(), "ready") }, "the command")
	u := openWebFromMenu(t, m, scr, opened)
	// Nothing printed: the confirmation shows in the overlay, and goes.
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(scr.text(), u) {
		t.Errorf("the URL is printed in the terminal")
	}

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

// fakeXDGOpen puts first in PATH an xdg-open which writes down the URL it
// was asked to open, in the file returned.
func fakeXDGOpen(t *testing.T, e env) string {
	t.Helper()
	bin := e.root + "/bin"
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	opened := e.root + "/opened"
	if err := os.WriteFile(bin+"/xdg-open", []byte("#!/bin/sh\necho \"$1\" > "+opened+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return opened
}

// openWebFromMenu opens the session's web UI with Ctrl-] w, and returns
// the URL given to xdg-open.
func openWebFromMenu(t *testing.T, m *os.File, scr *screen, opened string) string {
	t.Helper()
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
	return u
}

// TestSessionWebProtected: the session's own web UI registers its port as
// hallpass web does, so that its sandbox and those of the other sessions
// that mediate the network cannot connect to it, until the session exits.
func TestSessionWebProtected(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			t.Setenv("XDG_RUNTIME_DIR", e.runtime)
			opened := fakeXDGOpen(t, e)
			flags := []string{"--mode=" + mode, "--mediate=write,exec,connect", "--allow-net=all", "--allow-path=/"}
			script := fmt.Sprintf(`
echo ready
while [ ! -e go ]; do sleep 0.05; done
HALLPASS_E2E_HELPER=net %q self connect "127.0.0.1:$(cat port)"
exec sleep 60
`, self)
			m, scr, c, done := runTermAfter(t, e, "", script, flags...)
			t.Cleanup(func() { _ = c.Process.Kill() })
			waitFor(t, func() bool { return strings.Contains(scr.text(), "ready") }, "the command")
			u := openWebFromMenu(t, m, scr, opened)
			port := strings.TrimSuffix(strings.TrimPrefix(u, "http://127.0.0.1:"), "/")

			file := fmt.Sprintf("%s/web-%d.port", sessionapi.SocketDir(), c.Process.Pid)
			if b, err := os.ReadFile(file); err != nil || string(b) != port+"\n" {
				t.Errorf("%s: %q, %v; want %s", file, b, err, port)
			}
			p, _ := strconv.ParseUint(port, 10, 16)
			if !slices.Contains(sessionapi.ProtectedPorts(), uint16(p)) {
				t.Errorf("port %s not in %v", port, sessionapi.ProtectedPorts())
			}

			// Another session, started after.
			o := e.cmd(fmt.Sprintf(`HALLPASS_E2E_HELPER=net %q other connect 127.0.0.1:%s`, self, port), append(flags, "--prompt=deny")...)
			out, err := o.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "other=denied\n") {
				t.Errorf("other session: %v\n%s", err, out)
			}

			// This session.
			if err := os.WriteFile(e.proj+"/port", []byte(port), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.proj+"/go", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { return strings.Contains(scr.text(), "self=") }, "the connect")
			if !strings.Contains(scr.text(), "self=denied") {
				t.Errorf("this session: not denied")
			}

			_ = c.Process.Signal(syscall.SIGTERM)
			_ = c.Wait()
			<-done
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Errorf("%s after exit: %v", file, err)
			}
			if t.Failed() {
				t.Logf("screen:\n%s", scr.text())
			}
		})
	}
}
