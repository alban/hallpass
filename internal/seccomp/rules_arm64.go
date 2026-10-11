// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package seccomp

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_AARCH64

// x32 does not exist on arm64.
const x32Bit = 0

// Rules returns the syscall rules for arm64. arm64 has only the *at variants.
func Rules(allowUserns bool) []Rule {
	return commonRules(allowUserns)
}
