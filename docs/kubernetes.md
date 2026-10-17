# Kubernetes

`hallpass-node` runs AI agents in pods under hallpass, in lite mode
(seccomp user notification). It is a DaemonSet: on each node, an
[NRI](https://github.com/containerd/nri) plugin adds a seccomp policy to
the containers that opt in, and a seccomp agent mediates their file
writes as `hallpass` does on a workstation. You answer their requests
through a gRPC session API on the agent pod, with the `hallpass-node`
client or the [Headlamp plugin](#headlamp-plugin).

!!! warning
    Experimental. Lite mode only.

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

`hallpass web` does the same in a browser, through the same
port-forward: the pending requests, the activity and the rules of every
session on that node, named `namespace/pod/container`.

```
hallpass web --node 127.0.0.1:7323                  # prints a pairing link
```

<video src="../assets/demos/kube-web.mp4" poster="../assets/demos/kube-web.png" controls muted playsinline aria-label="kubectl exec into a sandboxed pod on the left and hallpass web --node on the right: a write in /workspace goes through, a write to /etc/profile is denied from the browser, a write to /etc/agent.conf is allowed once"></video>

*The pod's shell waits while the question is in the browser on another machine; denying it fails the write in the pod.*

The agent also logs every request, answer and session
(`kubectl -n hallpass-system logs`).

The decisions are Events on the pod, shown by `kubectl describe pod` and
`kubectl get events`: `HallpassAllowed` and `HallpassDenied` for each
answer and who gave it, `HallpassNotAnswered` when a request timed out,
and `HallpassPolicyDenied` for the denials of the policy and of the
built-in rules, without a human (the first one at once, then at most a
summary per minute per container, with the most frequent paths):

```
Warning  HallpassPolicyDenied  container agent: denied by the policy: write /etc/a1
Warning  HallpassPolicyDenied  container agent: denied by the policy 5 times in the last 1m0s: write /etc/a2 (2), write /etc/a0 (1), write /etc/a1 (1) and 1 more
```

Allowed accesses without a human are not reported. Events expire
(after an hour by default); the agent's log keeps everything.

## Headlamp plugin

The [Headlamp](https://headlamp.dev) plugin in
[headlamp/](https://github.com/alban/hallpass/tree/main/headlamp) answers
requests from the browser. It connects to every `hallpass-node` pod
through the API server's port-forward, as `kubectl port-forward` does,
and needs nothing more in the cluster.

<video src="../assets/demos/headlamp.mp4" poster="../assets/demos/headlamp.png" controls muted playsinline aria-label="kubectl exec on the left and Headlamp on the right: Sandbox with hallpass sets the policy on a Deployment, then a write to /etc/profile in its new pod is denied from the hallpass view and a write to /etc/agent.conf is allowed once"></video>

*Sandboxing a Deployment is a pod action; its requests then show in the app bar badge, on every page.*

Build it (Go, Node.js and npm):

```
make headlamp            # headlamp/dist/{main.js,main.wasm.gz}
make headlamp-package    # headlamp/hallpass-0.1.0.tar.gz
```

Install it in Headlamp's plugin directory, in a `hallpass` directory with
`main.js`, `main.wasm.gz` and `package.json`:

- Headlamp desktop: `~/.config/Headlamp/plugins/hallpass/` on Linux
  (Settings > Plugins shows where on other systems).
- Headlamp in a cluster or in a container: the directory given by
  `-plugins-dir` (`/headlamp/plugins` in the image), for example from
  an init container or a volume holding the tarball's content.

```
mkdir -p ~/.config/Headlamp/plugins/hallpass
cp headlamp/dist/main.js headlamp/dist/main.wasm.gz headlamp/package.json \
   ~/.config/Headlamp/plugins/hallpass/
```

It adds:

- **hallpass** in the sidebar: the pending requests of the cluster, the
  sessions (pod, container, node, policy) and the agents' connection
  state. Each request has the answer buttons `once`, `temp`, `always`,
  `deny` and `never`.
- A badge in the app bar with the number of pending requests, on every
  page. A blocked container waits for an answer.
- A **hallpass** section in the details of a mediated pod: its policy,
  pending requests and rules.
- A **hallpass** column in the pod list: `mediated`, or the number of
  pending requests.
- **Sandbox with hallpass**, a pod action: it sets or removes
  `hallpass.io/policy` on the pod template of the pod's Deployment,
  StatefulSet, DaemonSet or CronJob. Only containers created with the
  annotation are mediated: a Deployment, or a StatefulSet or DaemonSet
  with a rolling update, replaces its pods; with `OnDelete`, a
  StatefulSet `partition` or a ReplicaSet without a Deployment, delete
  the pods yourself; a CronJob changes from its next Job. The dialog says
  which. The namespace still needs the
  `hallpass.io/enabled=true` label. Bare pods and Jobs cannot change:
  edit their manifest instead.

The user needs to list pods in `hallpass-system` and to create
`pods/portforward` there. Whoever has these permissions can answer for
every mediated container in the cluster: grant them like `exec` into the
mediated pods. The sandbox action also needs to list
`hallpasspolicies` and to patch the workload.

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
- **Startup and API server outages.** The agent registers with NRI
  first, then refuses the opted-in containers (they fail to start and
  the kubelet retries) until it has read the namespaces and
  HallpassPolicies; it is Ready from then on (`hallpass-node ready`, its
  readiness probe). If the API server becomes unreachable later,
  mediation goes on with the last state read, but answering through
  `port-forward` fails: requests wait until their `askTimeout`.
- Policy changes apply to containers started afterwards.
- No authentication on the session API beyond Kubernetes' own on
  `port-forward`: whoever can port-forward to `hallpass-system` pods can
  answer for every session of that node, from the CLI or from Headlamp.
