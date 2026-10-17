#!/usr/bin/env bash
# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# Answers the kind e2e's requests through the Headlamp plugin: the
# E2E_ANSWER command of test/kind/e2e.sh (make test-headlamp-kind). Runs
# Headlamp with the plugin from headlamp/dist in docker, on the host
# network, and drives it with Puppeteer (e2e.js). Then sandboxes a
# Deployment with the plugin's pod action.
#
# Environment, from e2e.sh:
#   KUBECONTEXT      the kind cluster's context
#   WORK             scratch directory
# Optional:
#   HEADLAMP_IMAGE   default Headlamp v0.46.0, pinned by digest
#   HEADLAMP_PORT    default 14466
#   CHROMIUM         browser to drive (default /snap/bin/chromium)
#   PROFILE          browser profile directory; the Chromium snap only
#                    writes under ~/snap/chromium/common/
#   HEADLAMP_E2E_KEEP  directory to copy the screenshots and Headlamp's log
#                    to

set -euo pipefail

cd "$(dirname "$0")"
: "${KUBECONTEXT:?}" "${WORK:?}"
IMAGE=${HEADLAMP_IMAGE:-ghcr.io/headlamp-k8s/headlamp:v0.46.0@sha256:8a0ef97527544baa2b35825940ddf4db6e2d09c30cd5aa31fd269ff604cc8b75}
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

# npm writes node_modules/.package-lock.json once an install completes.
[ node_modules/.package-lock.json -nt package-lock.json ] || npm ci --no-audit --no-fund

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
# A Deployment for the "Sandbox with hallpass" action, which adds the
# policy annotation to its pod template.
kubectl --context "$KUBECONTEXT" -n hallpass-e2e create deployment sandboxed \
	--image "${BUSYBOX:-busybox:1.37}" -- sleep 3600 >/dev/null
kubectl --context "$KUBECONTEXT" -n hallpass-e2e rollout status deployment/sandboxed --timeout=120s >/dev/null
SANDBOX_POD=$(kubectl --context "$KUBECONTEXT" -n hallpass-e2e get pod -l app=sandboxed \
	-o jsonpath='{.items[0].metadata.name}')
URL="http://127.0.0.1:$PORT" CLUSTER="$KUBECONTEXT" SHOTS="$WORK/shots" SANDBOX_POD=$SANDBOX_POD \
	node e2e.js || status=$?
if [ $status = 0 ]; then
	got=$(kubectl --context "$KUBECONTEXT" -n hallpass-e2e get deployment sandboxed \
		-o jsonpath='{.spec.template.metadata.annotations.hallpass\.io/policy}')
	[ "$got" = e2e ] || { echo "deployment sandboxed: policy annotation '$got', want e2e" >&2; status=1; }
fi
kubectl --context "$KUBECONTEXT" -n hallpass-e2e delete deployment sandboxed --wait=false >/dev/null || true
if [ -n "${HEADLAMP_E2E_KEEP:-}" ]; then
	mkdir -p "$HEADLAMP_E2E_KEEP"
	cp -r "$WORK/shots" "$HEADLAMP_E2E_KEEP/"
	docker logs "$NAME" >"$HEADLAMP_E2E_KEEP/headlamp.log" 2>&1 || true
fi
exit $status
