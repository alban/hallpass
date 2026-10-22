// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alban/hallpass/internal/rules"
)

// TestApplyCheck checks that Decision.Check judges the rules as applied,
// their paths resolved, and that a refusal changes nothing.
func TestApplyCheck(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	m, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Apply(Decision{AddRules: []rules.Rule{tree(dir, rules.Allow)}}); err != nil {
		t.Fatal(err)
	}
	_, before, gen := m.Snapshot()

	refused := errors.New("refused")
	var add, removed []rules.Rule
	d := Decision{
		RemoveRules: []uint64{before[0].ID},
		AddRules:    []rules.Rule{tree(link, rules.Allow)},
		Check: func(a, r, _ []rules.Rule) error {
			add, removed = a, r
			return refused
		},
	}
	if _, err := m.Apply(d); !errors.Is(err, refused) {
		t.Fatalf("Apply: %v, want %v", err, refused)
	}
	if len(add) != 1 || add[0].Object.Path.Path != target || add[0].ID == 0 {
		t.Errorf("checked %+v, want %s resolved", add, target)
	}
	if len(removed) != 1 || removed[0].ID != before[0].ID {
		t.Errorf("checked removed %+v, want %+v", removed, before)
	}
	_, after, gen2 := m.Snapshot()
	if gen2 != gen || len(after) != 1 || after[0].ID != before[0].ID {
		t.Errorf("refused Apply changed the rules: %+v at %d, was %+v at %d", after, gen2, before, gen)
	}

	d.Check = func(a, r, _ []rules.Rule) error { return nil }
	if _, err := m.Apply(d); err != nil {
		t.Fatal(err)
	}
	_, after, _ = m.Snapshot()
	if len(after) != 1 || after[0].Object.Path.Path != target || after[0].ID != add[0].ID {
		t.Errorf("rules %+v, want %+v", after, add)
	}
}
