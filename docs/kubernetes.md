# Kubernetes

`hallpass-node` runs AI agents in pods under hallpass, in lite mode
(seccomp user notification). It is a DaemonSet: on each node, an
[NRI](https://github.com/containerd/nri) plugin adds a seccomp policy to
the containers that opt in, and a seccomp agent mediates their file
writes as `hallpass` does on a workstation. You answer their requests
through a gRPC session API on the agent pod.

!!! warning
    Experimental. Lite mode only; no Headlamp plugin yet.

## Requirements

- containerd 2.2 or later, with NRI enabled (the default in containerd
  2.x). Check with `containerd config dump`: the
  `io.containerd.nri.v1.nri` plugin has `disable = false`.
- If the NRI default validator is enabled
  (`[plugins.'io.containerd.nri.v1.nri'.default_validator] enable = true`),
  it must not reject seccomp adjustments
  (`reject_unconfined_seccomp_adjustment`,
  `reject_runtime_default_seccomp_adjustment`,
  `reject_custom_seccomp_adjustment`).
- runc. With runc 1.5 or later and Linux 5.19 or later, the agent sets
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, so a signal does not
  interrupt a mediated syscall while it waits for an answer
  (`--wait-killable`, detected with `runc features`).
- CRI-O and nodes without NRI are not supported.

## Install

Build the image and deploy it:

```
docker build -f deploy/kubernetes/Dockerfile -t <registry>/hallpass-node:<tag> .
docker push <registry>/hallpass-node:<tag>
cd deploy/kubernetes && kustomize edit set image ghcr.io/alban/hallpass-node=<registry>/hallpass-node:<tag>
kubectl apply -k deploy/kubernetes
```

This creates:

- the `HallpassPolicy` CRD (`hallpasspolicies.hallpass.io`, cluster-scoped);
- the namespace `hallpass-system`, with the `hallpass-node` DaemonSet,
  its service account and a cluster role reading namespaces and
  `hallpasspolicies`.

The DaemonSet runs privileged with `hostPID`, mounts `/var/run/nri` and
`/run/hallpass` from the host, and uses the pod network: its session
API listens on the pod's loopback, `127.0.0.1:7323`, with no
authentication, so it is only reachable through `kubectl port-forward`.

## Opt in

A container is mediated only if both hold:

1. its namespace matches the agent's `--namespace-selector` (default
   `hallpass.io/enabled=true`), chosen by the cluster admin in the
   DaemonSet;
2. its pod has the annotation `hallpass.io/policy: <name>`, naming a
   `HallpassPolicy`.

Every other container is untouched. If an opted-in pod names a policy
that does not exist, its containers fail to start.

```yaml
apiVersion: hallpass.io/v1alpha1
kind: HallpassPolicy
metadata:
  name: agent
spec:
  allow: [/workspace/**, /tmp/**]
  deny: [/var/run/secrets/**]
  ask: true            # false: deny without asking
  askTimeout: 5m       # no answer in time: deny
```

- `allow` and `deny` are paths in the container: `/workspace/**` and
  `/workspace` both mean `/workspace` and everything under it. Other
  globs and relative paths are rejected. Deny wins.
- Also allowed: `/dev/null` and the other harmless devices, the
  terminal (`/dev/tty`, `/dev/pts`) and `/dev/termination-log`.
- `ask` (default `true`): ask about the other writes. With `false`, they
  are denied at once.
- `askTimeout` (default `5m`): a request with no answer by then is
  denied.

The syscalls mediated are the same as `hallpass`'s: writes, renames,
links, removals... (see [How it works](design.md)), and new user and
mount namespaces are refused. The policy is merged into the container's
own seccomp profile (`RuntimeDefault`, `Localhost` or `Unconfined`):
hallpass's rules first, the rest kept.

[deploy/kubernetes/sample.yaml](https://github.com/alban/hallpass/blob/main/deploy/kubernetes/sample.yaml)
has a complete example.

## Answer requests

Each mediated container is a session, until its process exits. A
`kubectl exec` into it joins the same session. Build the client
(`make hallpass-node`) and forward the agent's port of the node running
the pod:

```
kubectl -n hallpass-system get pods -o wide        # find the agent on the pod's node
kubectl -n hallpass-system port-forward pod/hallpass-node-xxxxx 7323:7323 &

hallpass-node sessions                              # sessions on that node
hallpass-node pending agents/agent/agent            # namespace/pod/container, or a session id
hallpass-node answer agents/agent/agent 1 once
```

Answers are those of `hallpass`: `once`, `temp` (until the session
ends), `always` (a rule for the session's lifetime: nothing is written
back to the policy), `deny` and `never`. `--addr` selects another
address than `127.0.0.1:7323`.

The agent also logs every request, answer and session
(`kubectl -n hallpass-system logs`).

## Limitations

- **Agent restarts.** The seccomp notify fds live in the agent: if it
  stops, the mediated syscalls of running containers fail with `ENOSYS`
  until they restart. Hence `updateStrategy: OnDelete`: to upgrade,
  delete the agent pod of a node when no mediated pod runs there.
- **Fail open.** A container created while the agent is not running is
  not mediated. To fail closed, enable the NRI default validator and list
  the plugin (`hallpass`) in its `required_plugins`, or add the annotation
  `required-plugins.noderesource.dev: '[hallpass]'` to the pod (also
  checked by the default validator).
- Policy changes apply to containers started afterwards.
- No authentication on the session API beyond Kubernetes' own on
  `port-forward`: whoever can port-forward to `hallpass-system` pods can
  answer for every session of that node.
