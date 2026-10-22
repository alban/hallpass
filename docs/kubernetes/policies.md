# Opt in and policies

## Opt in

A container is mediated only if both hold:

1. its namespace matches the agent's `--namespace-selector` (default
   `hallpass.io/enabled=true`), chosen by the cluster admin in the
   DaemonSet;
2. its pod has the annotation `hallpass.io/policy: <name>`, naming a
   `HallpassPolicy`.

Every other container is untouched. If an opted-in pod names a policy
that does not exist, its containers fail to start.

In Headlamp, the **Sandbox with hallpass** pod action sets the
annotation on the pod's workload (see
[Headlamp plugin](answer.md#headlamp-plugin)).

## HallpassPolicy

```yaml
apiVersion: hallpass.io/v1alpha1
kind: HallpassPolicy
metadata:
  name: agent
spec:
  prompt: true         # false: deny without asking
  promptTimeout: 5m    # no answer in time: deny
  mediate: [write, exec, connect]  # default: write, exec
  groups:
    "@build": [/usr/bin/make, /usr/bin/cc, /usr/local/go/bin/**]
  rules: |
    allow write /workspace/**
    allow write /tmp/**
    deny  write /var/run/secrets/**
    ask   write /workspace/.git/hooks/**   # hooks run outside the sandbox
    allow exec  /usr/bin/make
    allow exec  /usr/local/go/bin/**
    allow exec  @shells
    allow exec  @git
    allow exec  @build
    deny  exec  /usr/bin/curl
    allow connect tcp:*:443
    allow connect unix:@my-service
    ask   connect tcp:10.0.0.1:22
    deny  connect 169.254.169.254
```

`rules` has one rule per line, in the syntax of `hallpass answer add`
and of [rule files](../workstation/usage.md#rule-files): a value with a
blank or a character other than letters, digits and `/._-+*~@:=%[]` is
quoted (`"/workspace/My Documents/**"`), `#` at the start of a word
starts a comment, and `group @NAME PROGRAM...` defines a group as
`groups` does (a name is defined once, in either).
Paths are the container's, with no variables (`$HOME`). The most
specific rule decides, an ask wins over an allow as specific, and a deny
wins over both. A pod naming a policy with an invalid rule fails to
start, as for a missing policy.

- `write PATH`: `/workspace/**` is `/workspace` and everything under it,
  `/workspace/file` that file only. Other globs and relative paths are
  rejected. Also allowed, without a rule: `/dev/null` and the other
  harmless devices, the terminal (`/dev/tty`, `/dev/pts`) and
  `/dev/termination-log`.
- `exec PROGRAM`: programs in the container, like paths:
  `/usr/bin/make` is that program, `/opt/tools/**` every program below
  `/opt/tools`. `allow exec @NAME` allows a group of programs, resolved
  in the container: `@shells`, `@coreutils`, `@search`, `@git`,
  `@busybox` (see [Programs](../workstation/usage.md#programs)), or one of
  `groups`; for a busybox image, `allow exec @busybox` lets its shell
  and applets run. They need `exec` in `mediate`. Also allowed, by a
  fixed rule: the container's command (its first argument, looked up in
  the container's `$PATH`), with any arguments, any number of times,
  also through `kubectl exec`. Other programs are asked about, and a
  prompt about a program of a group offers the group. Programs are
  matched by path only: an allowed interpreter runs any code it is given
  (`python3 -c`, `bash -c`), `ld.so /path/to/program` runs a program
  without executing it, a copy of a program under an allowed path runs,
  busybox applets installed as symlinks are all the same program, a
  `binfmt_misc` handler needs an allow in strict mode (it is never
  asked about), and a `memfd` is never allowed for good. See
  [Programs](../workstation/usage.md#programs) for details.
- `connect DESTINATION`: destinations in the `--allow-connect` syntax
  ([Network](../workstation/usage.md#network-experimental)); `all` is every
  destination, unix sockets included. They need `connect` in `mediate`.
  Loopback and unix listeners started in the container are allowed
  without asking. A host name (`allow connect ghcr.io:443`, or
  `*.githubusercontent.com:443`) matches the addresses the container's
  own DNS answers gave it; the cloud metadata addresses are denied
  unless a rule names them.
- `http METHOD... URL`: HTTPS requests through hallpass-node's proxy
  (`allow http GET https://ghcr.io/**`), see
  [HTTPS requests](../workstation/usage.md#https-requests-experimental).

The other fields:

- `prompt` (default `true`): ask about the other writes and programs. With
  `false`, they are denied at once, and so are requests made in advance.
- `promptTimeout` (default `5m`): a request with no answer by then is
  denied (`ETIMEDOUT` for a request made in advance). `0` waits forever,
  like `hallpass --timeout=0`.
- `mediate` (default `[write, exec]`): the syscall categories mediated.
  `exec` asks about the programs the container runs. `connect`
  (experimental) asks about connections and sends, like
  `hallpass --mediate` ([Network](../workstation/usage.md#network-experimental)).
  A request made in advance fails at once with `ENOSYS` when its
  category is left out (`write`, `exec` or `connect`, as the request's
  operation).
- `groups`: groups of programs of the policy's own, by name: a new
  group (`@build` above), or a replacement for the built-in group of the
  same name. Their programs are paths in the container, as in `exec`
  rules, resolved when the container starts. `allow exec @NAME` allows
  them, and a prompt about one of their programs offers the group. Names
  are `@`, a lowercase letter, then lowercase letters, digits or `-`.
  They need `exec` in `mediate`.

The fields `rules` replaced (`allowPaths`, `denyPaths`, `askPaths`,
`allowConnect`, `denyConnect`, `askConnect`, `allowExec`, `denyExec`) are refused:
the API server rejects a policy that has them.

Policy changes apply to containers started afterwards: a running
session keeps the policy it started with.

The syscalls mediated are the same as `hallpass`'s: writes, renames,
links, removals... (see [Files](../how-it-works/files.md)), plus the programs
run with `exec` in `mediate`, connections and sends with `connect`, and new user and
mount namespaces are refused. The policy is merged into the container's
own seccomp profile (`RuntimeDefault`, `Localhost` or `Unconfined`):
hallpass's rules first, the rest kept.

[deploy/kubernetes/sample.yaml](https://github.com/alban/hallpass/blob/main/deploy/kubernetes/sample.yaml)
has a complete example.

## Credentials

A `credential NAME` line keeps a token out of the container: the
container gets a placeholder in the profile's variable (`GH_TOKEN` for
`gh`), and hallpass-node's HTTPS proxy puts the real value on the wire,
to the credential's hosts only (see
[Credentials](../workstation/usage.md#credentials-experimental)). The
value is a key of a Secret in the pod's namespace, never mounted in the
pod:

```yaml
apiVersion: hallpass.io/v1alpha1
kind: HallpassPolicy
metadata: {name: ci}
spec:
  mediate: [write, connect]
  rules: |
    allow connect github.com:443
    allow http GET https://api.github.com/**
    credential gh
  credentials:
    gh: {secretRef: {name: gh-token, key: token}}
```

hallpass-node reads no Secret by default. The namespace's owner grants
it the ones its pods use, by name:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: hallpass-credentials, namespace: ci}
rules:
  - apiGroups: [""]
    resources: [secrets]
    resourceNames: [gh-token]
    verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: hallpass-credentials, namespace: ci}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: hallpass-credentials}
subjects:
  - {kind: ServiceAccount, name: hallpass-node, namespace: hallpass-system}
```

Without the grant, or without the Secret, the container is not created,
with the reason in its events. The value stays in hallpass-node's
memory; a restart of the agent before the container starts loses it
(requests then carry the placeholder). A request carrying the
credential to another host is refused and reported as a
`HallpassCredentialLeak` Warning Event on the pod: a tripwire for the
naive attempt, not the protection (see
[Credentials](../workstation/usage.md#credentials-experimental)).
