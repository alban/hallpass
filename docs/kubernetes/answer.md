# Answer requests

## With the CLI or `hallpass web`

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

The answers are the same as on a workstation: `once`, `temp` (5
minutes), `always` (for the session's lifetime: nothing is written back
to the policy), `deny` and `never`; see
[Answers and rules](../answers/index.md). `--addr` selects another address
than `127.0.0.1:7323`. A request made
[in advance](../workstation/usage.md#asking-in-advance) by a program in the
container takes `grant` or `deny`; `hallpass-node pending` shows its
duration and its reason, the program's own words.

[`hallpass web`](../answers/web.md) does the same in a browser, through the same
port-forward: the pending requests, the activity and the rules of every
session on that node, named `namespace/pod/container`.

```
hallpass web --node 127.0.0.1:7323                  # prints a pairing link
```

<video src="../../assets/demos/kube-web.mp4" poster="../../assets/demos/kube-web.png" controls muted playsinline aria-label="kubectl exec into a sandboxed pod on the left and hallpass web --node on the right: a write in /workspace goes through, a write to /etc/profile is denied from the browser, a write to /etc/agent.conf is allowed once"></video>

*The pod's shell waits while the question is in the browser on another machine; denying it fails the write in the pod.*

## Logs and Events

The agent logs every request, answer and session
(`kubectl -n hallpass-system logs`).

The decisions are Events on the pod, shown by `kubectl describe pod` and
`kubectl get events`: `HallpassStarted` when a container's sandbox
starts (mode, policy, and how to answer), `HallpassAllowed` and
`HallpassDenied` for each
answer and who gave it, `HallpassNotAnswered` when a request timed out,
and `HallpassPolicyDenied` for the denials of the policy and of the
built-in rules, without a human (the first one at once, then at most a
summary per minute per container, with the most frequent paths):

```
Normal   HallpassStarted       container agent: sandboxed by hallpass (strict mode, policy "agent"); answer its requests with Headlamp or `hallpass web --node`
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

<video src="../../assets/demos/headlamp.mp4" poster="../../assets/demos/headlamp.png" controls muted playsinline aria-label="kubectl exec on the left and Headlamp on the right: Sandbox with hallpass sets the policy on a Deployment, then a write to /etc/profile in its new pod is denied from the hallpass view and a write to /etc/agent.conf is allowed once"></video>

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
  `deny` and `never`; a request made in advance shows its folder, its
  duration and the program's reason, marked as unverified, with `grant`
  and `deny`.
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

## Who can answer

There is no authentication on the session API beyond Kubernetes' own
on `port-forward`. The user needs to list pods in `hallpass-system` and
to create `pods/portforward` there. Whoever has these permissions can
answer for every mediated container in the cluster, from the CLI or
from Headlamp: grant them like `exec` into the mediated pods. The
Headlamp sandbox action also needs to list `hallpasspolicies` and to
patch the workload.

If the API server is unreachable, answering through `port-forward`
fails: requests wait until their `askTimeout`.
