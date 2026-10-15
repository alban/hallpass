# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash

# Multi-arch image with an uncompressed boot/vmlinux per architecture
# (github.com/inspektor-gadget/ci-kernels). Pin a patch release, not a moving tag.
CI_KERNELS_IMAGE ?= ghcr.io/inspektor-gadget/ci-kernels:7.2.8-debug

# grpcnotrace drops gRPC's golang.org/x/net/trace (and html/template): 4 MB.
GO_TAGS ?= grpcnotrace

.PHONY: all
all:
	go build -tags '$(GO_TAGS)' -o hallpass ./cmd/hallpass

# Run the tests in a VM booting ci-kernels:KERNEL_VERSION, which has BPF-LSM
# active. Needs vimto (CGO_ENABLED=0 go install lmb.io/vimto@latest) and qemu.
# Without /dev/kvm, qemu emulates the CPU: slower, but it works. Everything is
# built on the host: vimto runs go test with -exec, and the e2e tests use the
# binary from HALLPASS_BIN instead of building it in the VM. vimto -sudo runs
# the tests as root in the VM only, so nothing on the host needs sudo.
# HALLPASS_REQUIRE_LSM=1 makes the strict-mode tests fail rather than skip.
VIMTO ?= vimto
KERNEL_VERSION ?= 7.2.8
TEST_VM_KERNEL ?= ghcr.io/inspektor-gadget/ci-kernels:$(KERNEL_VERSION)
TEST_VM_PKGS ?= ./...
TEST_VM_FLAGS ?=
.PHONY: test-vm
test-vm: all
	$(if $(wildcard /dev/kvm),,VIMTO_DISABLE_KVM=1) CGO_ENABLED=0 \
	HALLPASS_BIN=$(CURDIR)/hallpass \
		$(VIMTO) -smp cpus=2 -sudo -kernel $(TEST_VM_KERNEL) -- \
		go test -count=1 $(TEST_VM_FLAGS) $(TEST_VM_PKGS)

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
