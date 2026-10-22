// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package monitor

import "github.com/alban/hallpass/internal/seccomp"

// listener is a seccomp listener: none outside Linux, where no syscall is
// notified (the website's demo makes its requests itself).
type listener struct{}

func (l *listener) close() {}

func syscallTable() []seccomp.Rule { return nil }
