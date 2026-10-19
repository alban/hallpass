// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/programs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

func TestValidate(t *testing.T) {
	no := false
	p, err := Spec{
		Allow:      []string{"/workspace/**", "/tmp", "/home/agent/.cache/", "/**"},
		Deny:       []string{"/var/run/secrets/**"},
		Ask:        &no,
		AskTimeout: "30s",
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	want := Policy{
		Allow:      []string{"/workspace", "/tmp", "/home/agent/.cache", "/"},
		Deny:       []string{"/var/run/secrets"},
		AskTimeout: 30 * time.Second,
		Mediate:    seccomp.DefaultCategories,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v, want %+v", p, want)
	}

	p, err = Spec{}.Validate()
	if err != nil || !p.Ask || p.AskTimeout != DefaultAskTimeout || p.Mediate != seccomp.DefaultCategories {
		t.Errorf("defaults: %+v, %v", p, err)
	}
	if p, err = (Spec{AskTimeout: "0"}).Validate(); err != nil || p.AskTimeout != 0 {
		t.Errorf("askTimeout 0: %+v, %v", p, err)
	}

	p, err = Spec{Mediate: []string{"files", "exec", "network"}, AllowNetwork: []string{"all"}, DenyNetwork: []string{"tcp:169.254.169.254"}}.Validate()
	if err != nil || p.Mediate != seccomp.AllCategories || len(p.AllowNetwork) != 1 || !p.AllowNetwork[0].AnyNet || p.DenyNetwork[0].NetString() != "tcp:169.254.169.254" {
		t.Errorf("network: %+v, %v", p, err)
	}

	for _, tc := range []struct {
		spec  Spec
		field string
	}{
		{Spec{Allow: []string{"workspace/**"}}, "allow"},
		{Spec{Allow: []string{"/work*/x"}}, "allow"},
		{Spec{Deny: []string{"/a/**/b"}}, "deny"},
		{Spec{AskTimeout: "soon"}, "askTimeout"},
		{Spec{AskTimeout: "-1s"}, "askTimeout"},
		{Spec{Mediate: []string{"dns"}}, "mediate"},
		{Spec{Mediate: []string{}}, "mediate"},
		{Spec{Mediate: []string{""}}, "mediate"},
		{Spec{AllowNetwork: []string{"all"}}, "allowNetwork"},
		{Spec{Mediate: []string{"network"}, DenyNetwork: []string{"tcp:nowhere"}}, "denyNetwork"},
		{Spec{AskNetwork: []string{"tcp:*:22"}}, "askNetwork"},
		{Spec{Mediate: []string{"network"}, AskNetwork: []string{"tcp:nowhere"}}, "askNetwork"},
		{Spec{AllowExec: []string{"ls"}}, "allowExec"},
		{Spec{AllowExec: []string{"/usr/*/ls"}}, "allowExec"},
		{Spec{Mediate: []string{"files"}, DenyExec: []string{"/usr/bin/curl"}}, "denyExec"},
		{Spec{AllowExec: []string{"@nope"}}, "allowExec"},
		{Spec{DenyExec: []string{"@shells"}}, "denyExec"},
		{Spec{Groups: map[string][]string{"tools": {"/opt/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@Tools": {"/opt/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"/opt/*/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"@shells"}}}, "groups"},
		{Spec{Mediate: []string{"files"}, Groups: map[string][]string{"@tools": {"/opt/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"/opt/x"}}, AllowExec: []string{"@tool"}}, "allowExec"},
	} {
		_, err := tc.spec.Validate()
		var fe *FieldError
		if !errors.As(err, &fe) || fe.Field != tc.field {
			t.Errorf("%+v: got %v, want an error on %s", tc.spec, err, tc.field)
		}
	}
}

func TestDefaults(t *testing.T) {
	p, err := Spec{
		Allow:        []string{"/workspace"},
		Deny:         []string{"/workspace/.git"},
		Mediate:      []string{"files", "network"},
		AllowNetwork: []string{"unix:@x"},
		DenyNetwork:  []string{"tcp:*:22"},
		AskNetwork:   []string{"tcp:10.0.0.1"},
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	d := p.Defaults(Context{Home: "/root", Allow: []string{"/dev/null"}, Deny: []string{"/etc/hallpass"}, OwnListeners: true, Lexical: true})
	rs := d.Rules()
	for path, want := range map[string]rules.Verdict{
		"/workspace/a":      rules.Allow,
		"/workspace/.git/x": rules.Deny,
		"/dev/null":         rules.Allow,
		"/etc/hallpass/x":   rules.Deny,
	} {
		if got, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: path}}, time.Now()); !ok || got != want {
			t.Errorf("write %s: %v %v, want %v", path, got, ok, want)
		}
	}
	if _, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: "/elsewhere"}}, time.Now()); ok {
		t.Error("/elsewhere matched a rule")
	}
	var nets []string
	for _, r := range rs {
		if r.Object.Path == nil {
			nets = append(nets, r.Verdict.String()+" "+r.Object.NetString())
		}
	}
	if want := []string{"allow own-listeners", "deny tcp:*:22", "allow unix:@x", "ask tcp:10.0.0.1"}; !reflect.DeepEqual(nets, want) {
		t.Errorf("network rules %q, want %q", nets, want)
	}
}

func TestExec(t *testing.T) {
	p, err := Spec{
		AllowExec: []string{"/opt/tools/**", "@shells", "/usr/bin/make", "@shells"},
		DenyExec:  []string{"/usr/bin/curl"},
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	want := []rules.PathMatch{{Path: "/opt/tools", Tree: true}, {Path: "/usr/bin/make"}}
	if !reflect.DeepEqual(p.AllowExec, want) || len(p.DenyExec) != 1 || p.DenyExec[0].Path != "/usr/bin/curl" {
		t.Fatalf("got %+v %+v", p.AllowExec, p.DenyExec)
	}
	if !reflect.DeepEqual(p.AllowGroups, []string{"@shells"}) {
		t.Fatalf("groups %q", p.AllowGroups)
	}
	rs := p.Defaults(Context{
		Home: "/root", Execs: []string{"/usr/bin/bash", "/usr/bin/curl"}, Lexical: true,
		Groups: []programs.Group{{Name: "@shells", Members: []string{"/usr/bin/dash"}}, {Name: "@git", Members: []string{"/usr/bin/git"}}},
	}).Rules()
	for path, want := range map[string]rules.Verdict{
		"/opt/tools/bin/x": rules.Allow,
		"/usr/bin/make":    rules.Allow,
		"/usr/bin/bash":    rules.Allow,
		"/usr/bin/dash":    rules.Allow,
		"/usr/bin/curl":    rules.Deny, // a deny wins over an implicit allow
	} {
		if got, _, ok := rules.Eval(rs, rules.OpExec, rules.Object{Path: &rules.PathObject{Path: path}}, time.Now()); !ok || got != want {
			t.Errorf("exec %s: %v %v, want %v", path, got, ok, want)
		}
	}
	for _, path := range []string{"/usr/bin/make2", "/usr/bin/git"} {
		if _, _, ok := rules.Eval(rs, rules.OpExec, rules.Object{Path: &rules.PathObject{Path: path}}, time.Now()); ok {
			t.Errorf("%s matched a rule", path)
		}
	}
	if v, _, ok := rules.Eval(rs, rules.OpWrite, rules.Object{Path: &rules.PathObject{Path: "/opt/tools/bin/x"}}, time.Now()); ok && v == rules.Allow {
		t.Error("an exec allow allows writes")
	}
}

// TestGroups: a policy's groups add to the built-in ones or replace them,
// and allowExec names them.
func TestGroups(t *testing.T) {
	p, err := Spec{
		Groups: map[string][]string{
			"@tools":  {"/opt/tools/**", "/usr/bin/make/"},
			"@shells": {"/usr/bin/dash"},
		},
		AllowExec: []string{"@tools"},
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	want := []programs.Def{{Name: "@shells", Members: []string{"/usr/bin/dash"}}, {Name: "@tools", Members: []string{"/opt/tools/**", "/usr/bin/make"}}}
	if !reflect.DeepEqual(p.Groups, want) || !reflect.DeepEqual(p.AllowGroups, []string{"@tools"}) {
		t.Fatalf("got %+v %q", p.Groups, p.AllowGroups)
	}
	defs := p.GroupDefs()
	if defs[0].Name != "@shells" || !reflect.DeepEqual(defs[0].Members, []string{"/usr/bin/dash"}) || defs[len(defs)-1].Name != "@tools" || len(defs) != len(programs.Builtin())+1 {
		t.Errorf("GroupDefs: %+v", defs)
	}
}
