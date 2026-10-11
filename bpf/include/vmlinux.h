/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright The hallpass Authors */

/*
 * Kernel types, generated per architecture with
 *   bpftool btf dump file /sys/kernel/btf/vmlinux format c > $ARCH/vmlinux.h
 * The generated headers apply preserve_access_index to every struct, so CO-RE
 * relocations fix field offsets up against the running kernel's BTF.
 * bpf2go defines __TARGET_ARCH_* for each target it builds.
 */
#if defined(__TARGET_ARCH_x86)
#include "amd64/vmlinux.h"
#elif defined(__TARGET_ARCH_arm64)
#include "arm64/vmlinux.h"
#else
#error "unsupported architecture"
#endif
