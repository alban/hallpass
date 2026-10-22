// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

package dnsredirect

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type hp_addr6 -type hp_dns_listener dnsredirect ../../bpf/dnsredirect.bpf.c -- -I../../bpf/include -O2 -g -Wall -Werror -mcpu=v3 -fms-extensions -Wno-microsoft-anon-tag
