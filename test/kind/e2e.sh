#!/usr/bin/env bash
# Copyright The hallpass Authors
# SPDX-License-Identifier: Apache-2.0

# End-to-end test of the hallpass node agent on kind (make test-kind).
#
# Creates a kind cluster (unless KIND_CLUSTER names an existing one), checks
# that its containerd has NRI on and allows seccomp adjustments, deploys
# hallpass-node built from this tree, and runs test/kind/e2e.yaml: a mediated
# pod writes /workspace (allowed by its policy) and two files outside it; the
# test answers "once" to the first and "deny" to the second through the
# session API (kubectl port-forward), and checks the pod's output. A pod
# without the annotation and an annotated pod in a namespace the agent does
# not select must run unmediated.
#
# Needs docker, kind, kubectl and go; the node pulls busybox from Docker Hub.
#
# Environment:
#   KIND_CLUSTER     cluster name (default hallpass-e2e)
#   KIND_NODE_IMAGE  node image for a new cluster (default kindest/node:v1.37.0,
#                    containerd 2.3)
#   KEEP_CLUSTER=1   keep a cluster this script created
#   BUSYBOX          test image (default busybox:1.37)
#   HALLPASS_E2E_WORK  parent of the scratch directory (default: the repository)
#   E2E_ANSWER       command that answers the two requests instead of the
#                    CLI, with KUBECONTEXT and WORK set (test/kind/headlamp)

set -euo pipefail

cd "$(dirname "$0")/../.."
CLUSTER=${KIND_CLUSTER:-hallpass-e2e}
NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.37.0}
BUSYBOX=${BUSYBOX:-busybox:1.37}
IMAGE=hallpass-node:e2e
PORT=${HALLPASS_E2E_PORT:-17323}
KUBECTL=(kubectl --context "kind-$CLUSTER")
WORK=$(mktemp -d "${HALLPASS_E2E_WORK:-$PWD}/.e2e-work.XXXXXX")
CLIENT=$WORK/hallpass-node
ADDR=127.0.0.1:$PORT
created=0
pf=

log() { echo "--- $*"; }
fail() {
	echo "FAIL: $*" >&2
	"${KUBECTL[@]}" -n hallpass-system logs ds/hallpass-node --tail=50 >&2 || true
	exit 1
}

cleanup() {
	[ -n "$pf" ] && kill "$pf" 2>/dev/null || true
	"${KUBECTL[@]}" delete --ignore-not-found --wait=false -f "$WORK/e2e.yaml" >/dev/null 2>&1 || true
	if [ "$created" = 1 ] && [ "${KEEP_CLUSTER:-}" != 1 ]; then
		kind delete cluster --name "$CLUSTER"
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# wait_for <seconds> <command...>: retry until the command succeeds.
wait_for() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@"; do
		[ $SECONDS -lt $deadline ] || return 1
		sleep 1
	done
}

if ! kind get clusters | grep -qx "$CLUSTER"; then
	log "creating kind cluster $CLUSTER ($NODE_IMAGE)"
	kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 120s
	created=1
fi
NODE=$CLUSTER-control-plane

log "checking containerd and NRI on $NODE"
docker exec "$NODE" containerd --version
docker exec "$NODE" containerd config dump >"$WORK/containerd.toml"
nri=$(sed -n "/^  \[plugins.'io.containerd.nri.v1.nri'\]/,/^  \[plugins.'io.containerd.runtime/p" "$WORK/containerd.toml")
[ -n "$nri" ] || fail "containerd has no NRI plugin (need containerd >= 2.2)"
grep -q '^    disable = false' <<<"$nri" || fail "NRI is disabled in containerd"
if grep -q '^      enable = true' <<<"$nri" &&
	grep -Eq '^      reject_(unconfined|runtime_default|custom)_seccomp_adjustment = true' <<<"$nri"; then
	fail "the NRI default validator rejects seccomp adjustments"
fi

log "building and loading $IMAGE"
docker build -q -f deploy/kubernetes/Dockerfile -t "$IMAGE" .
kind load docker-image --name "$CLUSTER" "$IMAGE"
CGO_ENABLED=0 go build -o "$CLIENT" ./cmd/hallpass-node

log "deploying hallpass-node"
"${KUBECTL[@]}" apply -k test/kind
"${KUBECTL[@]}" wait --for=condition=Established crd/hallpasspolicies.hallpass.io --timeout=60s
# updateStrategy is OnDelete: replace the agent to run the image just loaded.
"${KUBECTL[@]}" -n hallpass-system delete pod -l app.kubernetes.io/name=hallpass-node --wait=true
agent_ready() {
	"${KUBECTL[@]}" -n hallpass-system logs ds/hallpass-node 2>/dev/null | grep -q 'Started plugin'
}
wait_for 120 agent_ready || fail "hallpass-node did not start"

log "starting the test pods"
sed "s|BUSYBOX|$BUSYBOX|" test/kind/e2e.yaml >"$WORK/e2e.yaml"
"${KUBECTL[@]}" delete --ignore-not-found --wait=true -f "$WORK/e2e.yaml" >/dev/null
"${KUBECTL[@]}" apply -f "$WORK/e2e.yaml"

"${KUBECTL[@]}" -n hallpass-system port-forward ds/hallpass-node "$PORT:7323" >"$WORK/port-forward.log" 2>&1 &
pf=$!
api_ready() { "$CLIENT" sessions --addr "$ADDR" >/dev/null 2>&1; }
wait_for 30 api_ready || fail "session API not reachable through port-forward"

# request_for <path>: the id of the mediated pod's pending request for path.
request_for() {
	"$CLIENT" pending --addr "$ADDR" hallpass-e2e/mediated/agent 2>/dev/null |
		awk -v p="$1" '$3 == p { print $1; exit }'
}
answer() {
	local path=$1 ans=$2 id=
	has_request() { id=$(request_for "$path") && [ -n "$id" ]; }
	wait_for 180 has_request || fail "no request for $path"
	log "answering $ans to request $id ($path)"
	"$CLIENT" answer --addr "$ADDR" hallpass-e2e/mediated/agent "$id" "$ans"
}
if [ -n "${E2E_ANSWER:-}" ]; then
	# Another client answers, e.g. the Headlamp plugin (test/kind/headlamp).
	log "answering with $E2E_ANSWER"
	KUBECONTEXT="kind-$CLUSTER" WORK=$WORK "$E2E_ANSWER" || fail "$E2E_ANSWER failed"
else
	answer /etc/once once
	answer /etc/denied deny
fi

succeeded() {
	[ "$("${KUBECTL[@]}" -n "$1" get pod "$2" -o jsonpath='{.status.phase}')" = Succeeded ]
}
for p in hallpass-e2e/mediated hallpass-e2e/plain hallpass-e2e-off/unselected; do
	wait_for 120 succeeded "${p%/*}" "${p#*/}" || fail "pod $p did not succeed"
done

check_log() {
	local out
	out=$("${KUBECTL[@]}" -n "$1" logs "$2")
	grep -qx "$3" <<<"$out" || fail "pod $1/$2: want '$3' in its output, got: $out"
}
check_log hallpass-e2e mediated allowed=ok
check_log hallpass-e2e mediated once=ok
check_log hallpass-e2e mediated denied=denied
check_log hallpass-e2e plain plain=ok
check_log hallpass-e2e-off unselected unselected=ok

# Only the mediated pod had a session; it ended with the pod.
"${KUBECTL[@]}" -n hallpass-system logs ds/hallpass-node >"$WORK/agent.log"
grep -q 'msg="session started".*namespace=hallpass-e2e pod=mediated' "$WORK/agent.log" ||
	fail "no session for the mediated pod"
if grep -Eq 'msg="(session started|mediating container)".*pod=(plain|unselected)' "$WORK/agent.log"; then
	fail "an unmediated pod got a session"
fi
no_session() { ! "$CLIENT" sessions --addr "$ADDR" | grep -q hallpass-e2e/mediated; }
wait_for 30 no_session || fail "the mediated pod's session did not end"

log "PASS"
