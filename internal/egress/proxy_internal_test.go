// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package egress

import "testing"

// TestUpperToken: only upper-case methods reach the rules, which name
// them so: "post" is refused rather than missing deny http POST.
func TestUpperToken(t *testing.T) {
	for m, want := range map[string]bool{"GET": true, "PROPFIND": true, "post": false, "Get": false, "": false, "GET ": false, "G-T": false} {
		if upperToken(m) != want {
			t.Errorf("upperToken(%q) = %v", m, !want)
		}
	}
}
