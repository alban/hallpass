// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"reflect"
	"testing"
)

func TestWrapList(t *testing.T) {
	got := wrapList(" D: ", []string{"~/.ssh", "~/.gnupg", "/a/very/long/path", "x"}, 22)
	want := []string{
		" D: ~/.ssh, ~/.gnupg,",
		"    /a/very/long/path,",
		"    x",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if got := wrapList(" D: ", nil, 22); !reflect.DeepEqual(got, []string{" D: "}) {
		t.Errorf("empty: %q", got)
	}
}
