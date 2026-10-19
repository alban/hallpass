// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"strings"
	"testing"
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
