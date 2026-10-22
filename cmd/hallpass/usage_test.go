// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/alban/hallpass/internal/policy"
)

// TestHelpGroups checks that --help lists every flag under a topic.
func TestHelpGroups(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := os.Stderr
	os.Stderr = w
	_, code, ok := parseFlags([]string{"--help"}, false)
	os.Stderr = stderr
	w.Close()
	out, _ := io.ReadAll(r)
	if ok || code != 0 {
		t.Fatalf("--help: ok %v, code %d", ok, code)
	}
	help := string(out)
	if strings.Contains(help, "\nOther:\n") {
		t.Errorf("flags missing from flagGroups:\n%s", help[strings.Index(help, "\nOther:\n"):])
	}
	for _, g := range flagGroups {
		if !strings.Contains(help, "\n"+g.title+":\n") {
			t.Errorf("help lacks %q", g.title)
		}
	}
}

// TestHTTPFlagsNeedConnect: the --*-http flags without connect mediated
// are refused by their own name, not the rule file's.
func TestHTTPFlagsNeedConnect(t *testing.T) {
	for _, c := range []struct {
		mediate []string
		deny    []string
		want    string
	}{
		{nil, []string{"GET https://h/x"}, "--deny-http GET https://h/x: needs connect in --mediate (--mediate=write,exec,connect)"},
		{[]string{"write"}, []string{"GET https://h/x"}, "--deny-http GET https://h/x: needs connect in --mediate (--mediate=write,connect)"},
		{[]string{"write", "connect"}, []string{"GET https://h/x"}, ""},
	} {
		err := httpFlags(&policy.Spec{Mediate: c.mediate}, nil, nil, c.deny)
		if got := fmt.Sprint(err); (c.want == "" && err != nil) || (c.want != "" && got != c.want) {
			t.Errorf("mediate %v: got %v, want %q", c.mediate, err, c.want)
		}
	}
}
