// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/sessionapi"
)

// listenTCP listens on a loopback port outside the sandbox and returns it.
func listenTCP(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// TestProtected checks the denials no rule lifts, not even
// --allow-net=all and --allow-path=/: connections to the ports registered by
// `hallpass web`, before the session starts (web) and while it runs
// (live), and to the session sockets; writes to the socket directory.
// Clients cannot remove them. Without network mediation, connections are
// not looked at.
func TestProtected(t *testing.T) {
	for _, mode := range modes(t) {
		for _, tc := range []struct {
			name    string
			mediate string
			want    map[string]string
		}{
			{"mediated", "write,exec,connect", map[string]string{
				"web": "denied", "mapped": "denied", "other": "ok", "sock": "denied", "write": "denied", "live": "denied",
			}},
			{"not mediated", "write,exec", map[string]string{
				"web": "ok", "mapped": "ok", "other": "ok", "sock": "ok", "write": "denied", "live": "ok",
			}},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				e := newEnv(t)
				t.Setenv("XDG_RUNTIME_DIR", e.runtime)
				web, other, live := listenTCP(t), listenTCP(t), listenTCP(t)
				unregister, err := sessionapi.RegisterPorts([]uint16{web})
				if err != nil {
					t.Fatal(err)
				}
				defer unregister()
				self, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				script := fmt.Sprintf(`
H() { HALLPASS_E2E_HELPER=net "$HP_SELF" "$@"; }
D="$XDG_RUNTIME_DIR/hallpass"
H web connect 127.0.0.1:%[1]d
H mapped connect '[::ffff:127.0.0.1]:%[1]d'
H other connect 127.0.0.1:%[2]d
H sock connect "$(ls "$D"/*.sock | head -n 1)"
if echo x > "$D/x" 2>/dev/null; then echo write=ok; else echo write=denied; fi
while [ ! -e go ]; do sleep 0.05; done
H live connect 127.0.0.1:%[3]d
`, web, other, live)
				flags := []string{"--mode=" + mode, "--prompt=deny", "--mediate=" + tc.mediate, "--allow-path=/"}
				if strings.Contains(tc.mediate, "connect") {
					flags = append(flags, "--allow-net=all")
				}
				c := e.cmd(script, flags...)
				c.Env = append(c.Env, "HP_SELF="+self)
				var out strings.Builder
				c.Stdout, c.Stderr = &out, &out
				if err := c.Start(); err != nil {
					t.Fatal(err)
				}
				p := dialPrompts(t, e, c)
				// A second web UI, started while the sandbox runs. Its
				// file is that of a live process: hallpass's.
				if err := writePortFile(c.Process.Pid, live); err != nil {
					t.Fatal(err)
				}
				if tc.want["live"] == "denied" {
					waitPortRule(t, p, live)
					for _, d := range []*pb.Decision{
						{RemoveSets: []string{monitor.ProtectedSet}, Client: "test"},
						{RemoveRules: []uint64{protectedRuleID(t, p, live)}, Client: "test"},
						{AddRules: []*pb.Rule{{Ops: uint32(rules.OpNet), Object: &pb.ObjectMatch{Kind: &pb.ObjectMatch_AnyNet{AnyNet: true}}, Set: monitor.ProtectedSet}}, Client: "test"},
					} {
						if _, err := p.c.Apply(context.Background(), d); status.Code(err) != codes.PermissionDenied && status.Code(err) != codes.InvalidArgument {
							t.Errorf("apply %v: %v, want PermissionDenied or InvalidArgument", d, err)
						}
					}
				}
				if err := os.WriteFile(e.proj+"/go", nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := c.Wait(); err != nil {
					t.Fatalf("hallpass: %v\n%s", err, out.String())
				}
				for l, want := range tc.want {
					if !strings.Contains(out.String(), l+"="+want+"\n") {
						t.Errorf("%s: want %s", l, want)
					}
				}
				if t.Failed() {
					t.Logf("output:\n%s", out.String())
				}
			})
		}
	}
}

// writePortFile registers port as RegisterPorts does, for process pid.
func writePortFile(pid int, port uint16) error {
	dir := sessionapi.SocketDir()
	tmp := fmt.Sprintf("%s/.web-%d.tmp", dir, pid)
	if err := os.WriteFile(tmp, fmt.Appendf(nil, "%d\n", port), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fmt.Sprintf("%s/web-%d.port", dir, pid))
}

// waitPortRule waits until the session has a protected rule on port.
func waitPortRule(t *testing.T, p prompter, port uint16) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if protectedRuleID(nil, p, port) != 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no protected rule on port %d", port)
}

// protectedRuleID returns the ID of the protected rule on port, 0 if none.
func protectedRuleID(t *testing.T, p prompter, port uint16) uint64 {
	s, err := p.c.Snapshot(context.Background(), &pb.SnapshotRequest{})
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		return 0
	}
	for _, r := range s.Rules {
		if in := r.GetObject().GetInet(); in != nil && r.Set == monitor.ProtectedSet && in.PortLo == uint32(port) {
			return r.Id
		}
	}
	return 0
}

func TestProtectPorts(t *testing.T) {
	web := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	for _, tc := range []struct {
		node string
		want []uint16
	}{
		{"", []uint16{8080}},
		{"127.0.0.1:9000", []uint16{8080, 9000}},
		{"localhost:9000", []uint16{8080, 9000}},
		{"[::1]:9000", []uint16{8080, 9000}},
		{"10.0.0.1:9000", []uint16{8080}},
		{"unix:///run/x.sock", []uint16{8080}},
	} {
		if got := protectPorts(web, tc.node); !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v, want %v", tc.node, got, tc.want)
		}
	}
}
