// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package lsm

// -fms-extensions: since 6.19 (?) the kernel embeds tagged structs anonymously
// ("struct foo;" as a member), and so does its BTF dump in vmlinux.h.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type event -type hp_grant hallpass ../../bpf/hallpass.bpf.c -- -I../../bpf/include -O2 -g -Wall -Werror -mcpu=v3 -fms-extensions -Wno-microsoft-anon-tag
