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

# The Kubernetes node agent (docs/kubernetes.md), static.
.PHONY: hallpass-node
hallpass-node:
	CGO_ENABLED=0 go build -tags '$(GO_TAGS)' -o hallpass-node ./cmd/hallpass-node

# The advance request helper (docs/workstation/agents.md), static with
# musl: with musl-gcc when installed (musl-tools), with Docker otherwise.
# MUSL_GCC= forces Docker. Not part of all, which needs neither.
MUSL_GCC ?= musl-gcc
HALLPASS_REQUEST_CFLAGS ?= -static -Os -s -Wall -Wextra -Werror
.PHONY: hallpass-request
hallpass-request:
ifneq ($(and $(MUSL_GCC),$(shell command -v $(MUSL_GCC) 2>/dev/null)),)
	$(MUSL_GCC) $(HALLPASS_REQUEST_CFLAGS) -o hallpass-request cmd/hallpass-request/hallpass-request.c
else
	docker build -o type=local,dest=. cmd/hallpass-request
endif

# End-to-end test of hallpass-node on a kind cluster (see test/kind/e2e.sh).
# Needs docker, kind, kubectl and network access to Docker Hub.
.PHONY: test-kind
test-kind:
	test/kind/e2e.sh

# The Headlamp plugin (docs/kubernetes.md): the wasm client of the node
# agents, and the plugin itself in headlamp/dist. npm uses the registry
# configured in ~/.npmrc: the lockfiles' registry.npmjs.org URLs are
# rewritten to it (replace-registry-host).
.PHONY: headlamp-wasm
headlamp-wasm:
	GOOS=js GOARCH=wasm go build -tags '$(GO_TAGS)' -ldflags='-s -w' -trimpath \
		-o headlamp/main.wasm ./cmd/headlamp-wasm
	gzip -9 -n -f -k headlamp/main.wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" headlamp/src/wasm_exec.js

headlamp/node_modules: headlamp/package.json headlamp/package-lock.json
	cd headlamp && npm ci --no-audit --no-fund
	touch $@

.PHONY: headlamp
headlamp: headlamp-wasm headlamp/node_modules
	cd headlamp && npm run build

# Type-check, lint and unit-test the plugin.
.PHONY: test-headlamp
test-headlamp: headlamp-wasm headlamp/node_modules
	cd headlamp && npm run tsc && npm run lint && npm test

# Package the plugin as a tarball for Headlamp's plugin directory.
.PHONY: headlamp-package
headlamp-package: headlamp
	cd headlamp && npm run package

# The kind e2e test, answering through Headlamp with the plugin, driven by
# Puppeteer (test/kind/headlamp). Also needs Chromium (CHROMIUM, default
# /snap/bin/chromium) and the Headlamp image.
.PHONY: test-headlamp-kind
test-headlamp-kind: headlamp
	E2E_ANSWER=$(CURDIR)/test/kind/headlamp/answer.sh test/kind/e2e.sh

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
# vimto's default (about 64 MB) is too small for the test packages running in
# parallel: processes in the sandbox fail with ENOMEM.
TEST_VM_MEMORY ?= 1G
.PHONY: test-vm
test-vm: all
	$(if $(wildcard /dev/kvm),,VIMTO_DISABLE_KVM=1) CGO_ENABLED=0 \
	HALLPASS_BIN=$(CURDIR)/hallpass \
		$(VIMTO) -smp cpus=2 -memory $(TEST_VM_MEMORY) -sudo -kernel $(TEST_VM_KERNEL) -- \
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
