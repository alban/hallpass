# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# The hallpass node agent (cmd/hallpass-node), static. Build from the
# repository root, with the version (go build records none without the
# repository's .git, as in a git worktree):
#
#	docker build -f deploy/kubernetes/Dockerfile --build-arg VERSION=$(git describe --tags --always --dirty) -t hallpass-node:dev .

FROM golang:1.26 AS build
ARG VERSION=
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 go build -trimpath -tags grpcnotrace \
	-ldflags "-X github.com/alban/hallpass/internal/version.version=${VERSION}" \
	-o /hallpass-node ./cmd/hallpass-node

FROM scratch
COPY --from=build /hallpass-node /hallpass-node
ENTRYPOINT ["/hallpass-node"]
CMD ["run"]
