// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Package version is the version of the hallpass binaries.
package version

import "runtime/debug"

// version is set by make, and the hallpass-node image (git describe):
// go build records no commit in a git worktree, nor in a Docker build
// without the repository's .git.
var version string

// String is version, else the module version go recorded (a tag, or a
// pseudo-version with the commit, +dirty for local changes), else
// "unknown".
func String() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "unknown"
}
