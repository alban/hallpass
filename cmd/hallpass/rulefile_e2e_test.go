// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// TestRuleFile runs under the rules of a --rules file: its allows and
// denies apply, with ~ and $WORKDIR expanded, an exact path covers that
// file only, and an invalid line or a file in the project directory stops
// hallpass before the command runs.
func TestRuleFile(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			out := e.root + "/out"
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			file := e.root + "/test.rules"
			text := `# a rule file
allow write ` + out + `/**
deny  write $WORKDIR/denied/**   # even inside the project
allow write ~/exact
`
			if err := os.WriteFile(file, []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(e.proj+"/denied", 0o755); err != nil {
				t.Fatal(err)
			}
			script := `
w() { if (echo x > "$2") 2>/dev/null; then echo "$1=ok"; else echo "$1=denied"; fi; }
w out ` + out + `/f
w denied ./denied/f
w exact ~/exact
w sibling ~/exact2
w proj ./f
`
			c := e.cmd(script, "--mode="+mode, "--prompt=deny", "--rules="+file)
			b, err := c.CombinedOutput()
			if err != nil {
				t.Fatalf("%v\n%s", err, b)
			}
			got := outputMap(string(b))
			for k, v := range map[string]string{"out": "ok", "denied": "denied", "exact": "ok", "sibling": "denied", "proj": "ok"} {
				if got[k] != v {
					t.Errorf("%s: got %q, want %q\n%s", k, got[k], v, b)
				}
			}

			bad := e.root + "/bad.rules"
			if err := os.WriteFile(bad, []byte("allow write /ok/**\nallow write $NOPE/x\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			b, err = e.cmd("echo ran", "--mode="+mode, "--rules="+bad).CombinedOutput()
			if err == nil || strings.Contains(string(b), "ran") || !strings.Contains(string(b), "bad.rules:2: $NOPE") {
				t.Errorf("invalid rule file: %v\n%s", err, b)
			}

			inside := e.proj + "/my.rules"
			if err := os.WriteFile(inside, []byte("allow write /tmp/**\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			b, err = e.cmd("echo ran", "--mode="+mode, "--rules="+inside).CombinedOutput()
			if err == nil || strings.Contains(string(b), "ran") || !strings.Contains(string(b), "in the project directory") {
				t.Errorf("rule file in the project directory: %v\n%s", err, b)
			}
		})
	}
}
