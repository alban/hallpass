// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSources(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "token")
	if err := os.WriteFile(f, []byte("ghp_file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HALLPASS_TEST_TOKEN", " ghp_env ")
	for in, want := range map[string]string{
		"env:HALLPASS_TEST_TOKEN": "ghp_env",
		"file:" + f:               "ghp_file",
		"cmd:echo ghp_cmd":        "ghp_cmd",
	} {
		s, err := Parse(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(t.Context())
		if err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"env:HALLPASS_TEST_NONE", "file:" + dir + "/none", "cmd:false", "cmd:printf a\\nb"} {
		s, _ := Parse(in)
		if v, err := s.Get(t.Context()); err == nil {
			t.Errorf("%s: %q, no error", in, v)
		}
	}
	for _, in := range []string{"", "env:", "vault:x", "token"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q): no error", in)
		}
	}
}
