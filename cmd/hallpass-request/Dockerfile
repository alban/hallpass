# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# hallpass-request, static with musl, alone in an image: mount it in a pod
# with an image volume, or COPY --from it into another image (see
# docs/kubernetes/answer.md). Build from this directory, for the
# machine's architecture or several:
#
#	docker build -t hallpass-request:dev cmd/hallpass-request
#	docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/hallpass-request:<tag> --push cmd/hallpass-request
#
# or extract the binary only:
#
#	docker build -o type=local,dest=. cmd/hallpass-request

FROM alpine:3.24 AS build
RUN apk add --no-cache gcc musl-dev
COPY hallpass-request.c /src/
RUN gcc -static -Os -s -Wall -Wextra -Werror -o /hallpass-request /src/hallpass-request.c

FROM scratch
COPY --from=build /hallpass-request /hallpass-request
ENTRYPOINT ["/hallpass-request"]
