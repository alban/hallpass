# Kubernetes

Status: work item 1 (lite mode) implemented on branch `nri`; the cluster
API (option A) and the Headlamp plugin on branch `headlamp`. See the
implementation notes ([work item 1](#implementation-notes-work-item-1),
[Headlamp](#implementation-notes-headlamp)) for where they differ from
this design. User docs: [../kubernetes.md](../kubernetes.md).

Run AI agents in pods under hallpass, opted in per namespace and per pod,
and answer their requests from [Headlamp](https://headlamp.dev). Lite mode
first; strict mode (BPF-LSM) next, on nodes where it is active.

## Components

```
kubelet ──CRI──> containerd ──NRI──> hallpass-node (DaemonSet, one per node)
                     │                  ▲     gRPC session API on 127.0.0.1
                     └─runc─ seccomp fd ┘     (pod network, not hostNetwork)
                                                 ▲
 Headlamp plugin ──> kube-apiserver ──port-forward┘   (option A, chosen)
```

- **`hallpass-node`**, a DaemonSet, one process per node:
  - an **NRI plugin**: on `CreateContainer`, for opted-in pods, adds a
    seccomp policy that notifies hallpass's syscalls, with
    `listenerPath` set to its agent socket;
  - a **seccomp agent**: runc connects to `listenerPath` when it starts
    the container and sends the notify fd and the container state
    (pid, annotations) with `SCM_RIGHTS`, per the OCI seccomp agent
    protocol. The agent runs one `monitor.Monitor` per container;
  - the **session API** (`internal/sessionapi`), one gRPC server for all
    the node's sessions, each identified by pod, container and id.
- **Headlamp plugin**: Pending, Activity and Rules views (as in
  [web.md](web.md#views)), plus a "hallpass" section in the pod details
  page. It speaks gRPC to the agents over port-forward (option A).
- A separate binary, `cmd/hallpass-node`: client-go and NRI stay out of
  the `hallpass` binary.

## Requirements (checked)

- containerd 2.2 or later: it ships NRI v0.10, which added
  `ContainerAdjustment.SetLinuxSeccompPolicy` with `listener_path` and
  `listener_metadata` (containerd/nri b315f77). NRI is on by default in
  containerd 2.x. CRI-O: to check.
- runc 1.5 or later accepts `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` in
  the OCI `flags`, which hallpass uses today. It is not silent: an older
  runc (unknown flag), libseccomp < 2.6 or kernel < 5.19 make runc fail
  the container creation (`seccomp.FlagSupported`). The agent sets the
  flag only if the kernel supports it and `runc features` (run from the
  host root) lists it.
- No fallback for containerd without NRI (a `localhost/` profile from
  the node cannot carry a `listenerPath` set per container): such nodes
  are not supported.
- The NRI default validator can reject seccomp adjustments
  (`reject_custom_seccomp_adjustment`, ...): the cluster admin must allow
  them, at least for this plugin.

## Opt-in

A container is mediated only if both hold:

1. its namespace matches the node agent's `--namespace-selector`, a
   label selector set by the cluster admin in the DaemonSet (as
   `namespaceSelector` in admission webhooks; e.g.
   `hallpass.io/enabled=true`), checked with a namespace informer; and
2. the pod has the annotation `hallpass.io/policy: <name>`, naming a
   policy (see below).

Every other container is untouched: the plugin returns no adjustment.
The annotation alone is not enough, so a user who can create pods cannot
put hallpass in front of a namespace the admin did not choose; the
allowlist alone is not enough, so nothing changes for existing pods of an
allowed namespace.

## Strict mode

The DaemonSet already runs privileged, so it can load the BPF-LSM
programs itself (no root helper) where `bpf` is in the active LSMs.

The programs must be loaded once per node, not once per container: each
copy runs on every hook of every task on the host. Today one `lsm.LSM`
is one session: members are marked `1` in task storage and `Sync`
replaces the whole rule set. The node agent needs a session id in them:

- the member mark holds the session id (inherited on fork as today);
- rule and grant keys include it; `Sync` replaces one session's rules;
- ring buffer events carry it, and the agent routes them to the right
  monitor.

`monitor.Kernel` then becomes a per-session view of the shared `LSM`.

The first exec is the barrier: the container's first `execve` is
notified, so the agent marks the init process as a member (on
`Attach`) before it runs the container's binary.

Paths: `bpf_path_d_path` resolves from the task's root, so rule paths
are container paths already; `Sync` resolves them to inodes through
`/proc/<pid>/root`, like lite mode.

## Seccomp policy

The OCI profile is generated from hallpass's rule table
(`internal/seccomp`), so the cluster and the CLI mediate the same
syscalls:

- `Notify` rules become `SCMP_ACT_NOTIFY`.
- `NotifyIfWrite` (open, openat with a write flag) becomes one
  `SCMP_ACT_NOTIFY` rule per flag bit (`SCMP_CMP_MASKED_EQ`, bit, bit),
  since OCI ORs the rules of a syscall.
- `Errno` and `ErrnoIfNamespace` become `SCMP_ACT_ERRNO` rules, as in
  the runtime's default profile.

They are merged into the container's existing policy (`RuntimeDefault`,
`Localhost`, or none): hallpass's rules come first, the rest is kept. An
`Unconfined` pod gets `defaultAction: SCMP_ACT_ALLOW` plus hallpass's
rules.

## Paths

Lite mode resolves a path in the monitor's own view of the filesystem
(`procfs.Resolve`). The node agent (`hostPID`) resolves it through the
calling process's root, `/proc/<pid>/root/`: the per-process root, so a
chroot inside the container is handled too. Going through that prefix is
not enough on its own: the kernel follows an absolute symlink, or a `..`
at the top, from the agent's root, not the container's. `walk` already
resolves symlinks one component at a time; it gets a root to prefix and
to clamp absolute targets and `..` to. Rules and prompts use container
paths (`/workspace/x`, not `/run/containerd/.../rootfs/workspace/x`).

Work: a root parameter in `procfs.Resolve` and `walk` (the CLI passes
`/`); the "other mount namespace" check in the monitor compares with that
root instead of the monitor's.

## Policies

A `HallpassPolicy` (cluster-scoped, created by the admin) holds what the
CLI takes from its flags and config file:

```yaml
apiVersion: hallpass.io/v1alpha1
kind: HallpassPolicy
metadata:
  name: agent
spec:
  allow: [/workspace/**, /tmp/**, /home/agent/.cache/**]
  deny: [/var/run/secrets/**]
  ask: true            # false: deny without asking (audit-only pods)
  askTimeout: 5m       # no answer in time: deny
```

## Cluster API

Both options sit on the same agent and gRPC session API; only the last
hop differs, so one can be added after the other. **Decided: A**, as
Inspektor Gadget does; no CRDs for requests. B stays an option if
per-namespace RBAC or the audit log become necessary.

### A. gRPC over port-forward (as Inspektor Gadget's Headlamp plugin)

The plugin opens a port-forward (WebSocket through the API server and
the kubelet) to each agent pod and speaks gRPC over it, with a Go client
compiled to wasm.

- Reuses the session API as is; Activity is a live stream; nothing is
  stored in the API server.
- The agent listens on 127.0.0.1 in its pod network: other pods cannot
  reach it.
- Authorization is coarse: whoever may `create pods/portforward` on the
  agent pods answers for every namespace. Answers are in the agent's
  log, not in the API audit log.
- One stream per node per open Headlamp tab.

### B. CRDs

The agent mirrors its monitors into the API server and applies the
answers it reads back.

- **`HallpassSession`** (one per mediated container, owned by the pod,
  deleted with it): `status` has the pod, container, node, start time,
  the rules (with their sets and expiry), and the last 200 `Decided`
  events, written at most every few seconds.
- **`HallpassRequest`** (one per pending request, owned by the session):
  `spec` has the op, objects, subject chain, facts, and the prompt
  (text and choices) from the `Answer` RPC's mapping; `status.answer` is
  set by the user (once, temp, always, never, deny). The agent applies
  it, then deletes the request. A request whose syscall ended (the
  process died, another answer won) is deleted too.
- Removing a rule: an annotation on the session
  (`hallpass.io/remove-rule: <id>`).

In the workload's namespace, so RBAC delegates per namespace and owner
references clean up with the pod. The roles for these resources must not
be aggregated into `edit`/`admin`, or a workload with a broad service
account could answer for itself.

- Kubernetes RBAC per namespace, audit log, `kubectl get
  hallpassrequests -w`.
- Load: requests exist only while a thread waits for a human, so a few
  per session; fine for etcd. `Decided` events (thousands per second)
  must not become objects: only a capped, throttled list. A cap on
  pending requests per session stops a sandbox from flooding the API
  server with blocked threads.
- A request takes an API round trip (tens of ms) before it is shown.

## Headlamp plugin

Both a dedicated view and additions to the pod pages.

- Sidebar entry and route: pending requests across the cluster, the
  activity and the rules (the three views of `hallpass web`, in React).
- App bar badge (`registerAppBarAction`): the number of pending
  requests. A blocked workload waits on an answer: it must show on any
  page.
- Pod details section (`registerDetailsViewSection`): whether hallpass
  is on, the policy, the pod's pending requests and rules, answerable
  in place.
- Pod header action (`registerDetailsViewHeaderAction`): "Sandbox with
  hallpass". The filter is installed when the container is created, so
  it patches the owner's (Deployment...) pod template annotation and
  causes a rollout; it cannot apply to a running pod.
- Pod list column (`registerResourceTableColumnsProcessor`): pending
  count.

## Idea: substitute a file's content (to discuss, not planned)

Use case: deploy a container with one config file changed, without
rebuilding the image. A rule names a path and a content; an `openat` of
that path gets a memfd holding the content.

Lite mode can do it: the agent fills a memfd and makes it the result of
the syscall with `SECCOMP_IOCTL_NOTIF_ADDFD` and
`SECCOMP_ADDFD_FLAG_SEND`, atomically. To discuss:

- For a content fixed at deploy time, an NRI bind mount over the file
  at container creation is simpler: it also covers `stat`, `mmap` and
  `exec`, and costs nothing at run time. A memfd only wins for dynamic
  cases (content changed at run time, per process, per open).
- Cost: the filter traps writes today. Substituting reads means trapping
  every `openat` (seccomp cannot match paths), in the containers that
  have such a rule only.
- Leaks: `stat(path)` still shows the original size and inode,
  `/proc/self/fd/N` shows `memfd:`. Some programs read `st_size` bytes.
- Opens for writing: a sealed read-only copy, or a private writable one?
- Lite mode only: BPF-LSM can deny, not substitute.
- Who may set it: injecting content is a privilege beyond allow or deny
  (annotation or CRD, RBAC).

## Lifetime

- The notify fd lives in the agent. If the agent dies, the mediated
  syscalls of running containers fail with `ENOSYS` until the containers
  are restarted. v1: DaemonSet `updateStrategy: OnDelete`, documented.
  Later: keep the fds in a small, rarely updated holder process.
- If the agent is not running when a container starts, its NRI plugin is
  not registered (the registration lives as long as its connection to
  containerd), so the container starts without hallpass: open by
  default. To fail closed, the admin lists the plugin in the NRI default
  validator's `required_plugins`, or the pod requests it with the
  `required-plugins.noderesource.dev` annotation (e.g. `[hallpass]`). The plugin cannot add that
  annotation: it is set when the pod is created (a mutating admission
  webhook could add it to every opted-in pod).
- Between the plugin's adjustment and runc's start, an agent that died
  makes runc fail to connect to `listenerPath`: that container fails to
  start.
- Restarting a container gives a new session.

## Privileges

`hallpass-node` runs privileged with `hostPID` (it reads
`/proc/<pid>/{mem,root,cwd,fd}` of containers on its node) and mounts
`/var/run/nri` and its socket directory (`/run/hallpass`) from the host.
Its service account reads namespaces (for the selector), pods, and
`hallpasspolicies`.

## Testing

kind with a node image running containerd 2.2, NRI enabled, and the
default validator allowing seccomp adjustments; an e2e test creates a
pod writing outside `/workspace`, answers its request over the session
API (port-forward), and checks the write and the session's rules. The
same test answers through Headlamp with the plugin, driven by a
headless browser.

## Work items (branches)

1. `nri`: root-aware `procfs.Resolve`; OCI profile from the rule table;
   `cmd/hallpass-node` (NRI plugin, seccomp agent, one session API for
   the node); `HallpassPolicy`; manifests; kind e2e. Lite mode.
2. Strict mode on the node: one BPF load with session ids.
3. `headlamp`: the cluster API (A) and the plugin (`headlamp/`).
4. Later: the fd holder; CRI-O.

## Open questions

- Remove a rule: an annotation on the session (decided).
- The agent socket directory on the host: rely on its permissions
  (root-only, 0700), no peer check (decided).

## Implementation notes (work item 1)

Where `cmd/hallpass-node` (branch `nri`) differs from or adds to the
design above:

- **Paths.** `procfs.Resolve` takes a root (`procfs.Root`); the agent
  uses `/proc/<pid>/root` of the calling process and gets container
  paths back. It also checks that the directory it resolved from is the
  file the root names (`sameFile`): a detached mount (`fsopen`,
  `open_tree`) is named relative to its own root, so its name means
  nothing in the container and a clone could pass for an allowed path.
  Such opens are refused, except one case: runc 1.2+ reopens its exec
  FIFO through a detached procfs after loading the filter
  (`openat(<detached /proc/1/task/1/fd>, "7", O_WRONLY)`); a single
  component on a procfs directory whose magic link points to a FIFO or
  socket is reported as the special file `fifo:N`/`socket:N`, as
  `/proc/self/fd/N` already is.
- **Rules.** Policy paths are matched lexically (`defaults.NewLexical`):
  the agent does not resolve them in the container at start, since the
  container's root is not populated yet when the policy is built.
  Policy path syntax: `/x/**` or `/x` (the tree under `/x`); other globs
  and relative paths are rejected. `ask` defaults to true, `askTimeout`
  to 5m (must be positive).
- **Implicit allows** in a container: `defaults.DefaultAllows`
  (`/dev/null`, ...), `/dev/tty`, `/dev/pts` (the container's own
  devpts) and `/dev/termination-log`. No home or cache defaults.
- **Seccomp profile** (`internal/ociseccomp`): only the native
  architecture is kept (`architectures` of the original policy are
  dropped, as hallpass's rules use native syscall numbers). A container
  policy that already uses `SCMP_ACT_NOTIFY` (default action or any
  rule) or its own `listenerPath`, or that conditions a hallpass syscall
  in a way libseccomp cannot combine with hallpass's rule, is refused
  (container creation fails) rather than merged. `CLONE_NEWUSER` and
  `CLONE_NEWNS` are denied as with `--allow-userns=false`.
  `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` is set with
  `--wait-killable=auto` only if the kernel accepts it and
  `runc features`, run chrooted in `/proc/1/root`, lists it (runc 1.4.3
  in kind does not).
- **Policies** come from the `HallpassPolicy` CRD through a dynamic
  informer. A pod naming a missing policy, or a namespace lookup error,
  fails the container creation (fail closed once opted in). If the
  policy is gone when runc connects, the session has only the implicit
  allows and does not ask.
- **Startup.** The informers start without blocking: the agent registers
  with NRI at once, and until both caches have synced the lookups fail
  with `errNotSynced`, so opted-in containers are refused rather than
  started unmediated (waiting for the caches before registering left that
  window open, e.g. when the agent restarts during an API server outage).
  `Synchronize` marks the plugin registered; the end of `stub.Run` clears
  it. Both together set the gRPC health service of the session API to
  SERVING, checked by the exec readiness probe `hallpass-node ready` (the
  API is on the pod's loopback, out of reach of an httpGet or grpc
  probe). No liveness probe: a restart drops the running containers'
  listeners.
- **Sessions.** One per container id; `kubectl exec` (a new listener for
  the same container) attaches to the same monitor. A session ends when
  the monitor has no listener left. `listenerMetadata` is JSON
  `{namespace, pod, podUID, container, policy, home}`.
- **Session API.** One `sessionapi.Node` per node on `127.0.0.1:7323`.
  Backward compatible proto changes: a `List` RPC and `SessionInfo.id`;
  on the node agent, the other RPCs must select the session with the
  `hallpass-session` gRPC metadata key. The CLI's unix socket serves one
  session, ignores that key and keeps its peer checks; the agent's TCP
  listener has none.
- **Client.** `hallpass-node sessions|pending|answer --addr`, sessions
  named by id, id prefix or `namespace/pod/container`. Answers go
  through `internal/answer`, shared with `hallpass`.
- **RBAC.** Namespaces and `hallpasspolicies` (get, list, watch); pods
  are not read: the pod's labels and annotations come from NRI.
- **kind.** `kindest/node:v1.37.0` ships containerd 2.3.4 with NRI on
  and the default validator off, and runc 1.4.3: no node image changes.
  `make test-kind` (`test/kind/e2e.sh`) creates the cluster, deploys
  the agent and checks mediation, answers (once, deny) over
  port-forward, and that unselected pods are untouched.
- **Not done:** strict mode, the fd holder; policy changes do not
  affect running sessions.

## Implementation notes (Headlamp)

Branch `headlamp`, on top of `nri`:

- **Wasm client** (`cmd/headlamp-wasm`, `GOOS=js`). The plugin reuses
  the Go client rather than a TypeScript gRPC client: `internal/nodeclient`
  holds the node agent's client side (dial, session selection, lookup)
  without the monitor, so it builds for wasm; `nodeclient.Watch` lists the
  sessions every 2 s, follows each one's events, and reports the whole
  state (sessions, pending requests, rules) as JSON after each change.
  3.4 MB gzipped, shipped as `main.wasm.gz` next to `main.js` and
  fetched from Headlamp's plugin URL.
- **Port-forward.** The plugin opens
  `/api/v1/namespaces/hallpass-system/pods/<pod>/portforward?ports=7323`
  with Headlamp's `stream()` (its auth and cluster proxy), with the
  `v4.channel.k8s.io` subprotocols. Go only gets `send` and `close`
  callbacks and is fed the received messages: it decodes the
  channel.k8s.io framing (data and error channels, each starting with
  the port) into a `net.Conn` for gRPC. A write waits for the data
  channel's port header. One WebSocket carries one TCP connection: if
  it ends, the plugin reconnects with a backoff (1 s, doubling, up to
  30 s).
- **Agents.** The plugin watches the pods
  `app.kubernetes.io/name=hallpass-node` in `hallpass-system` and keeps
  one connection per running pod, so per node, while a page of the
  cluster is open. A store per cluster holds their state; the React
  components read it with `useSyncExternalStore`. Exceptions in the
  callbacks Go calls are caught: they would stop the wasm program.
  The four methods given to JS for a connection (`deliver`, `closed`,
  `answer`, `close`) are created once, with `js.FuncOf`, and bound to the
  connection's id (`Function.prototype.bind`): a `js.Func` per
  connection would leak, since releasing one that JS still calls
  panics, and the plugin reconnects for as long as a page is open.
- **UI.** The sidebar view has the pending requests, the sessions and
  the agents' state; the app bar badge, the pod details section (policy,
  pending requests, rules per container) and the pod list column
  (`N pending` or `mediated`) read the same store. The answers are those
  of `hallpass-node answer`, sent with client name `headlamp`. Not done:
  the Activity view and removing rules.
- **Sandbox with hallpass.** Follows the pod's controllers (ReplicaSet to
  Deployment, Job to CronJob; StatefulSet, DaemonSet) and merge-patches
  the annotation on the pod template, or removes it. Bare pods and Jobs
  cannot change their template: the dialog says so. It warns when the
  namespace lacks `hallpass.io/enabled=true`, the default selector.
- **Authorization** is option A's: `create pods/portforward` on the
  agent pods answers for the whole cluster.
- **Tests.** `make test-headlamp`: tsc, lint and vitest (the store's
  reconnects and answers, the sandbox's owner lookup and patch);
  `go test ./cmd/headlamp-wasm` runs gRPC to a `sessionapi.Node` through a
  simulated port-forward. `make test-headlamp-kind` runs the kind e2e
  with `E2E_ANSWER=test/kind/headlamp/answer.sh`: Headlamp v0.46.0
  (pinned by digest) in docker with the plugin, driven by Puppeteer
  and Chromium; it checks the badge, the column, the section, answers
  `once` and `deny`, and sandboxes a Deployment. The npm lockfiles
  name `registry.npmjs.org`; npm fetches from the configured registry
  instead (`replace-registry-host`). `demos/headlamp/record.js`
  records the demo on the same cluster.
