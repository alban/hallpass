# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# The hallpass node agent (cmd/hallpass-node), static. Build from the
# repository root:
#
#	docker build -f deploy/kubernetes/Dockerfile -t hallpass-node:dev .

FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
	CGO_ENABLED=0 go build -trimpath -tags grpcnotrace -o /hallpass-node ./cmd/hallpass-node

FROM scratch
COPY --from=build /hallpass-node /hallpass-node
ENTRYPOINT ["/hallpass-node"]
CMD ["run"]
