// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/opencontainers/runtime-spec/specs-go/features"

	"github.com/alban/hallpass/internal/ociseccomp"
	"github.com/alban/hallpass/internal/seccomp"
)

// runcPaths are where runc usually is on a node.
var runcPaths = []string{"/usr/local/sbin/runc", "/usr/local/bin/runc", "/usr/sbin/runc", "/usr/bin/runc"}

// waitKillable decides SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: mode is
// "true", "false" or "auto". Auto sets it only if the kernel knows it and
// runc lists it in `runc features`, run in hostRoot (runc fails the
// container creation on a flag it does not know). runc is its path in
// hostRoot, "" to search runcPaths.
func waitKillable(mode, hostRoot, runc string) (bool, string, error) {
	switch mode {
	case "true":
		return true, "forced", nil
	case "false":
		return false, "disabled", nil
	case "auto":
	default:
		return false, "", fmt.Errorf("--wait-killable: %q: want auto, true or false", mode)
	}
	if !seccomp.WaitKillableRecvSupported() {
		return false, "kernel does not support it", nil
	}
	flags, path, err := runcFlags(hostRoot, runc)
	if err != nil {
		return false, "", err
	}
	if !slices.Contains(flags, string(ociseccomp.FlagWaitKillableRecv)) {
		return false, path + " does not support it", nil
	}
	return true, path + " and the kernel support it", nil
}

// runcFlags returns the seccomp flags `runc features` lists.
func runcFlags(hostRoot, runc string) ([]string, string, error) {
	paths := runcPaths
	if runc != "" {
		paths = []string{runc}
	}
	for _, p := range paths {
		if _, err := os.Stat(filepath.Join(hostRoot, p)); err != nil {
			continue
		}
		cmd := exec.Command(p, "features")
		cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: hostRoot}
		cmd.Dir = "/"
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, p, fmt.Errorf("%s features: %w: %s", p, err, bytes.TrimSpace(stderr.Bytes()))
		}
		var f features.Features
		if err := json.Unmarshal(out, &f); err != nil {
			return nil, p, fmt.Errorf("%s features: %w", p, err)
		}
		if f.Linux == nil || f.Linux.Seccomp == nil {
			return nil, p, nil
		}
		return f.Linux.Seccomp.SupportedFlags, p, nil
	}
	return nil, "", fmt.Errorf("runc not found in %s (tried %v); set --runc or --wait-killable", hostRoot, paths)
}
