# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash

# Multi-arch image with an uncompressed boot/vmlinux per architecture
# (github.com/inspektor-gadget/ci-kernels). Pin a patch release, not a moving tag.
CI_KERNELS_IMAGE ?= ghcr.io/inspektor-gadget/ci-kernels:7.2.8-debug

.PHONY: all
all:
	go build -o hallpass ./cmd/hallpass

# Rebuild the BPF objects (needs clang); they are committed.
.PHONY: generate
generate:
	go generate ./internal/lsm

# Regenerate bpf/include/$ARCH/vmlinux.h from CI_KERNELS_IMAGE.
# Needs crane (github.com/google/go-containerregistry/cmd/crane), jq, bpftool.
.PHONY: update-vmlinux
update-vmlinux:
	TMP=$$(mktemp -d btfs-tmp.XXXXXXXXXX) && \
	pushd $$TMP && \
	crane pull --format oci $(CI_KERNELS_IMAGE) . && \
	MANIFEST_PATH=$$(jq -r '.manifests[0].digest' index.json | sed 's|:|/|g') && \
	jq -r '.manifests[] | .platform.architecture + ";" + .digest' blobs/$$MANIFEST_PATH \
		| while IFS=';' read -r ARCH DIGEST; do \
		mkdir -p $$ARCH && \
		ROOTFS_DIGEST=$$(jq -r '.layers[1].digest' blobs/$${DIGEST//:/\/}) && \
		tar -C $$ARCH -xf blobs/$${ROOTFS_DIGEST//:/\/} boot/vmlinux && \
		bpftool btf dump file $$ARCH/boot/vmlinux format c \
			> ../bpf/include/$$ARCH/vmlinux.h || exit 1; \
	done && \
	popd && \
	rm -rf $$TMP
