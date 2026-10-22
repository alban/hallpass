// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alban/hallpass/internal/programs"
	"github.com/alban/hallpass/internal/rules"
	"github.com/alban/hallpass/internal/seccomp"
)

func TestValidate(t *testing.T) {
	no := false
	p, err := Spec{
		AllowPaths:    []string{"/workspace/**", "/tmp", "/home/agent/.cache/", "/**"},
		DenyPaths:     []string{"/var/run/secrets/**"},
		AskPaths:      []string{"/workspace/.git/**"},
		Prompt:        &no,
		PromptTimeout: "30s",
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	want := Policy{
		AllowPaths:    []string{"/workspace", "/tmp", "/home/agent/.cache", "/"},
		DenyPaths:     []string{"/var/run/secrets"},
		AskPaths:      []string{"/workspace/.git"},
		PromptTimeout: 30 * time.Second,
		Mediate:       seccomp.DefaultCategories,
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v, want %+v", p, want)
	}

	p, err = Spec{}.Validate()
	if err != nil || !p.Prompt || p.PromptTimeout != DefaultPromptTimeout || p.Mediate != seccomp.DefaultCategories {
		t.Errorf("defaults: %+v, %v", p, err)
	}
	if p, err = (Spec{PromptTimeout: "0"}).Validate(); err != nil || p.PromptTimeout != 0 {
		t.Errorf("promptTimeout 0: %+v, %v", p, err)
	}

	p, err = Spec{Mediate: []string{"write", "exec", "connect"}, AllowNet: []string{"all"}, DenyNet: []string{"tcp:169.254.169.254"}}.Validate()
	if err != nil || p.Mediate != seccomp.AllCategories || len(p.AllowNet) != 1 || !p.AllowNet[0].AnyNet || p.DenyNet[0].NetString() != "tcp:169.254.169.254" {
		t.Errorf("network: %+v, %v", p, err)
	}

	for _, tc := range []struct {
		spec  Spec
		field string
	}{
		{Spec{AllowPaths: []string{"workspace/**"}}, "allowPaths"},
		{Spec{AllowPaths: []string{"/work*/x"}}, "allowPaths"},
		{Spec{DenyPaths: []string{"/a/**/b"}}, "denyPaths"},
		{Spec{AskPaths: []string{"relative"}}, "askPaths"},
		{Spec{AllowPaths: []string{""}}, "allowPaths"},
		{Spec{PromptTimeout: "soon"}, "promptTimeout"},
		{Spec{PromptTimeout: "-1s"}, "promptTimeout"},
		{Spec{Mediate: []string{"dns"}}, "mediate"},
		{Spec{Mediate: []string{"files"}}, "mediate"},
		{Spec{Mediate: []string{}}, "mediate"},
		{Spec{Mediate: []string{""}}, "mediate"},
		{Spec{AllowNet: []string{"all"}}, "allowNet"},
		{Spec{Mediate: []string{"connect"}, DenyNet: []string{"tcp:nowhere"}}, "denyNet"},
		{Spec{AskNet: []string{"tcp:*:22"}}, "askNet"},
		{Spec{Mediate: []string{"connect"}, AskNet: []string{"tcp:nowhere"}}, "askNet"},
		{Spec{AllowExec: []string{"ls"}}, "allowExec"},
		{Spec{AllowExec: []string{"/usr/*/ls"}}, "allowExec"},
		{Spec{Mediate: []string{"write"}, DenyExec: []string{"/usr/bin/curl"}}, "denyExec"},
		{Spec{AllowExec: []string{"@nope"}}, "allowExec"},
		{Spec{DenyExec: []string{"@shells"}}, "denyExec"},
		{Spec{Groups: map[string][]string{"tools": {"/opt/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@Tools": {"/opt/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"/opt/*/x"}}}, "groups"},
		{Spec{Groups: map[string][]string{"@tools": {"@shells"}}}, "groups"},
		{Spec{Mediate: []string{"write"}, Groups: map[string][]string{"@tools": {"/opt/x"}}}, "groups"},
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
		AllowPaths: []string{"/workspace"},
		DenyPaths:  []string{"/workspace/.git"},
		AskPaths:   []string{"/workspace/secret"},
		Mediate:    []string{"write", "connect"},
		AllowNet:   []string{"unix:@x"},
		DenyNet:    []string{"tcp:*:22"},
		AskNet:     []string{"tcp:10.0.0.1"},
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	d := p.Defaults(Context{Home: "/root", Allow: []string{"/dev/null"}, Deny: []string{"/etc/hallpass"}, OwnListeners: true, Lexical: true})
	rs := d.Rules()
	for path, want := range map[string]rules.Verdict{
		"/workspace/a":        rules.Allow,
		"/workspace/.git/x":   rules.Deny,
		"/workspace/secret/x": rules.Ask,
		"/dev/null":           rules.Allow,
		"/etc/hallpass/x":     rules.Deny,
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

// TestRules: the rules text and the rule files, their groups, variables
// and categories; the rules reach the Defaults' rules.
func TestRules(t *testing.T) {
	vars := func(name string) (string, error) {
		if name == "HOME" {
			return "/home/me", nil
		}
		return "", errors.New("unknown")
	}
	p, err := Spec{
		Mediate:   []string{"write", "exec", "connect"},
		Rules:     "allow exec @git\ndeny connect 169.254.169.254",
		RuleFiles: []RuleFile{{Name: "a.rules", Text: "allow write ~/out/**\nask write /etc/x"}},
		Vars:      vars,
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	var specs []string
	for _, r := range p.Rules {
		specs = append(specs, r.Spec())
	}
	if want := []string{"deny connect 169.254.169.254", "allow write /home/me/out/**", "ask write /etc/x"}; !reflect.DeepEqual(specs, want) || !reflect.DeepEqual(p.AllowGroups, []string{"@git"}) {
		t.Errorf("rules %q, groups %v", specs, p.AllowGroups)
	}
	d := p.Defaults(Context{Home: "/home/me", Lexical: true})
	found := map[string]bool{}
	for _, r := range d.Rules() {
		found[r.Spec()] = true
	}
	for _, want := range []string{"deny connect 169.254.169.254", "allow write /home/me/out/**", "ask write /etc/x"} {
		if !found[want] {
			t.Errorf("Defaults lack %q: %v", want, found)
		}
	}

	// A group a rule file defines is known to every rule and to
	// allowExec, wherever it is used; one may replace a built-in group.
	p, err = Spec{
		AllowExec: []string{"@build"},
		Rules:     "allow exec @git",
		RuleFiles: []RuleFile{{Name: "g.rules", Text: `group @build /usr/bin/make "/opt/my cc/**"` + "\ngroup @git /usr/local/bin/git"}},
	}.Validate()
	if err != nil {
		t.Fatal(err)
	}
	defs := map[string][]string{}
	for _, d := range p.GroupDefs() {
		defs[d.Name] = d.Members
	}
	if !reflect.DeepEqual(defs["@build"], []string{"/usr/bin/make", "/opt/my cc/**"}) || !reflect.DeepEqual(defs["@git"], []string{"/usr/local/bin/git"}) || !reflect.DeepEqual(p.AllowGroups, []string{"@build", "@git"}) {
		t.Errorf("groups %q, allowed %v", defs, p.AllowGroups)
	}

	for _, c := range []struct {
		spec Spec
		want string
	}{
		{Spec{Rules: "allow write $HOME/x"}, "rules: rules:1: $HOME: no variables"},
		{Spec{RuleFiles: []RuleFile{{Name: "b.rules", Text: "\nallow exec /x"}}, Mediate: []string{"write"}}, "rules: b.rules:2: needs exec in mediate"},
		{Spec{Rules: "allow connect all"}, "rules: rules:1: needs connect in mediate"},
		{Spec{Rules: "allow exec @nope"}, `rules: rules:1: "@nope": unknown group`},
		{Spec{Rules: "group @x /bin/a", Groups: map[string][]string{"@x": {"/bin/b"}}}, "rules: rules:1: @x: already defined (groups)"},
		{Spec{Rules: "group @x /bin/a", RuleFiles: []RuleFile{{Name: "b.rules", Text: "\ngroup @x /bin/b"}}}, "rules: b.rules:2: @x: already defined (rules:1)"},
		{Spec{Rules: "group @X /bin/a"}, `rules: rules:1: "@X": not a group name`},
		{Spec{Rules: "group @x rel/a"}, "rules: rules:1: @x:"},
		{Spec{Rules: "group @x @git"}, "rules: rules:1: @x:"},
		{Spec{Rules: "group @x /bin/a", Mediate: []string{"write"}}, "rules: rules:1: needs exec in mediate"},
	} {
		_, err := c.spec.Validate()
		var fe *FieldError
		if err == nil || !errors.As(err, &fe) || fe.Field != "rules" || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %s...", c.spec, err, c.want)
		}
	}
}
