// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/alban/hallpass/internal/lsm"
)

// modes returns the modes to test: lite, and strict when it can run.
func modes(t *testing.T) []string {
	m := []string{"lite"}
	if os.Geteuid() == 0 && lsm.Active() == nil {
		m = append(m, "strict")
	} else if os.Getenv("HALLPASS_REQUIRE_LSM") == "1" {
		t.Fatal("HALLPASS_REQUIRE_LSM=1: strict mode cannot run")
	}
	return m
}

// TestMediateExec checks that --mediate without files leaves writes alone,
// in the filter and, in strict mode, in the kernel.
func TestMediateExec(t *testing.T) {
	for _, mode := range modes(t) {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			c := e.cmd(`echo x > "$HOME/outside" && echo write=ok`, "--mode="+mode, "--ask=deny", "--mediate=exec")
			out, err := c.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "write=ok") {
				t.Errorf("%v\n%s", err, out)
			}
		})
	}
}

func TestMediateBad(t *testing.T) {
	e := newEnv(t)
	out, err := e.cmd("true", "--mediate=files,dns").CombinedOutput()
	if err == nil || !strings.Contains(string(out), `unknown category "dns"`) {
		t.Errorf("%v\n%s", err, out)
	}
}
