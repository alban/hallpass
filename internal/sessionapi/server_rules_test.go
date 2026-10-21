// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package sessionapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/alban/hallpass/api/session/v1"
	"github.com/alban/hallpass/internal/defaults"
	"github.com/alban/hallpass/internal/monitor"
	"github.com/alban/hallpass/internal/rulepb"
	"github.com/alban/hallpass/internal/rules"
)

func spec(t *testing.T, s string) *pb.Rule {
	t.Helper()
	r, err := rules.ParseSpec(s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return rulepb.To(r)
}

// TestApplyRules checks that the rules a client adds give no more than an
// answer could, unless they narrow an allow they replace.
func TestApplyRules(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	m, err := monitor.New(monitor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	flags := []rules.Rule{
		{Ops: rules.OpNet, Verdict: rules.Allow, Object: rules.ObjectMatch{AnyNet: true}, Set: defaults.Set},
		{Ops: rules.OpAll, Verdict: rules.Allow, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/srv", Tree: true}}, Set: defaults.Set},
		{Ops: rules.OpFiles, Verdict: rules.Deny, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: "/run/sock", Tree: true}}, Set: monitor.ProtectedSet},
	}
	if _, err := m.Apply(monitor.Decision{AddRules: flags}); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(m, fakeSession{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	conn, c, err := Dial(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	id := func(spec string) uint64 {
		t.Helper()
		snap, err := c.Snapshot(ctx, &pb.SnapshotRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range snap.Rules {
			if r.GetSpec() == spec {
				return r.Id
			}
		}
		t.Fatalf("no rule %q in %v", spec, snap.Rules)
		return 0
	}

	for _, tc := range []struct {
		name   string
		add    []string
		remove []string
		want   codes.Code
	}{
		{name: "a folder a prompt offers", add: []string{"allow write /opt/tool/**"}},
		{name: "a file", add: []string{"allow write /etc/hosts"}},
		{name: "a program", add: []string{"allow exec /usr/bin/git"}},
		{name: "a destination", add: []string{"allow connect tcp:1.2.3.4:443"}},
		{name: "a unix socket", add: []string{"allow connect unix:/run/x.sock"}},
		{name: "a /proc file", add: []string{"allow proc oom_score_adj chrome"}},
		{name: "deny anything", add: []string{"deny write /**", "deny connect all"}},
		{name: "ask anything", add: []string{"ask write /home/u/**"}},
		{name: "the root", add: []string{"allow write /**"}, want: codes.PermissionDenied},
		{name: "home", add: []string{"allow write /home/u/**"}, want: codes.PermissionDenied},
		{name: "a folder wider than offered", add: []string{"allow write /home/u/.config/**"}, want: codes.PermissionDenied},
		{name: "programs below", add: []string{"allow exec /usr/bin/**"}, want: codes.PermissionDenied},
		{name: "a network", add: []string{"allow connect 10.0.0.0/8:443"}, want: codes.PermissionDenied},
		{name: "every port", add: []string{"allow connect 1.2.3.4"}, want: codes.PermissionDenied},
		{name: "unknown paths", add: []string{"allow unknown"}, want: codes.PermissionDenied},
		{name: "everything", add: []string{"allow connect all"}, want: codes.PermissionDenied},
		{name: "narrow a flag", remove: []string{"allow connect all"}, add: []string{"allow connect 10.0.0.0/8"}},
		{name: "narrow a folder", remove: []string{"allow write /srv/**"}, add: []string{"allow write /srv/www/**"}},
		{name: "widen a folder", remove: []string{"allow write /srv/www/**"}, add: []string{"allow write /**"}, want: codes.PermissionDenied},
		{name: "a protected rule", remove: []string{"deny write /run/sock/**"}, want: codes.PermissionDenied},
	} {
		d := &pb.Decision{Client: "test"}
		for _, s := range tc.add {
			d.AddRules = append(d.AddRules, spec(t, s))
		}
		for _, s := range tc.remove {
			d.RemoveRules = append(d.RemoveRules, id(s))
		}
		_, err := c.Apply(ctx, d)
		if got := status.Code(err); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	// An edit applies to the rules it was made for only.
	snap, err := c.Snapshot(ctx, &pb.SnapshotRequest{})
	if err != nil {
		t.Fatal(err)
	}
	d := &pb.Decision{RemoveRules: []uint64{id("allow write /srv/www/**")}, AddRules: []*pb.Rule{spec(t, "allow write /srv/www/a/**")}, IfGeneration: snap.Generation + 1}
	if _, err := c.Apply(ctx, d); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("stale edit: %v", err)
	}
	d.IfGeneration = snap.Generation
	if _, err := c.Apply(ctx, d); err != nil {
		t.Errorf("edit: %v", err)
	}
	if _, err := c.Apply(ctx, &pb.Decision{AddRules: []*pb.Rule{{Ops: uint32(rules.OpAll), Object: &pb.ObjectMatch{Kind: &pb.ObjectMatch_Path{Path: &pb.PathMatch{Path: "rel"}}}}}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("relative path: %v", err)
	}

	// A narrower path is judged once resolved: through a symlink to "/",
	// it is not narrower.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(dir, "root")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(monitor.Decision{AddRules: []rules.Rule{{Ops: rules.OpAll, Verdict: rules.Allow, Object: rules.ObjectMatch{Path: &rules.PathMatch{Path: dir, Tree: true}}, Set: defaults.Set}}}); err != nil {
		t.Fatal(err)
	}
	d = &pb.Decision{RemoveRules: []uint64{id("allow write " + dir + "/**")}, AddRules: []*pb.Rule{spec(t, "allow write "+dir+"/root/**")}}
	if _, err := c.Apply(ctx, d); status.Code(err) != codes.PermissionDenied {
		t.Errorf("narrowing through a symlink: %v", err)
	}
}
