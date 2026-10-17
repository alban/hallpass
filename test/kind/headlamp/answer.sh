#!/usr/bin/env bash
# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# Answers the kind e2e's requests through the Headlamp plugin: the
# E2E_ANSWER command of test/kind/e2e.sh (make test-headlamp-kind). Runs
# Headlamp with the plugin from headlamp/dist in docker, on the host
# network, and drives it with Puppeteer (e2e.js).
#
# Environment, from e2e.sh:
#   KUBECONTEXT      the kind cluster's context
#   WORK             scratch directory
# Optional:
#   HEADLAMP_IMAGE   default ghcr.io/headlamp-k8s/headlamp:latest
#   HEADLAMP_PORT    default 14466
#   CHROMIUM         browser to drive (default /snap/bin/chromium)
#   PROFILE          browser profile directory; the Chromium snap only
#                    writes under ~/snap/chromium/common/
#   HEADLAMP_E2E_KEEP  directory to copy the screenshots and Headlamp's log
#                    to

set -euo pipefail

cd "$(dirname "$0")"
: "${KUBECONTEXT:?}" "${WORK:?}"
IMAGE=${HEADLAMP_IMAGE:-ghcr.io/headlamp-k8s/headlamp:latest}
PORT=${HEADLAMP_PORT:-14466}
DIST=../../../headlamp/dist
NAME=hallpass-e2e-headlamp-$$

for f in main.js main.wasm.gz; do
	[ -s "$DIST/$f" ] || { echo "no $DIST/$f: run make headlamp" >&2; exit 1; }
done
mkdir -p "$WORK/plugins/hallpass" "$WORK/shots"
cp "$DIST/main.js" "$DIST/main.wasm.gz" ../../../headlamp/package.json "$WORK/plugins/hallpass/"
chmod -R a+rX "$WORK/plugins"
kubectl config view --raw --minify --context "$KUBECONTEXT" >"$WORK/kubeconfig"
chmod 644 "$WORK/kubeconfig"

[ -d node_modules ] || npm install --no-audit --no-fund

cleanup() {
	docker logs "$NAME" >"$WORK/headlamp.log" 2>&1 || true
	docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker run -d --name "$NAME" --network host \
	-v "$WORK/kubeconfig:/kubeconfig:ro" -v "$WORK/plugins:/headlamp/plugins:ro" \
	"$IMAGE" -kubeconfig /kubeconfig -listen-addr 127.0.0.1 -port "$PORT" >/dev/null
deadline=$((SECONDS + 60))
until curl -sf "http://127.0.0.1:$PORT/config" >/dev/null; do
	[ $SECONDS -lt $deadline ] || { echo "Headlamp did not start" >&2; exit 1; }
	sleep 1
done

status=0
URL="http://127.0.0.1:$PORT" CLUSTER="$KUBECONTEXT" SHOTS="$WORK/shots" node e2e.js || status=$?
if [ -n "${HEADLAMP_E2E_KEEP:-}" ]; then
	mkdir -p "$HEADLAMP_E2E_KEEP"
	cp -r "$WORK/shots" "$HEADLAMP_E2E_KEEP/"
	docker logs "$NAME" >"$HEADLAMP_E2E_KEEP/headlamp.log" 2>&1 || true
fi
exit $status
