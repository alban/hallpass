// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"reflect"
	"testing"
	"time"

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
