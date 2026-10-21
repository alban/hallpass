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
  allowPaths: [/workspace/**, /tmp/**]
  denyPaths: [/var/run/secrets/**]
  askPaths: [/workspace/.git/hooks/**]
  prompt: true         # false: deny without asking
  promptTimeout: 5m    # no answer in time: deny
  mediate: [write, exec, connect]  # default: write, exec
  allowNet: ["tcp:*:443", "unix:@my-service"]
  denyNet: ["169.254.169.254"]
  askNet: ["tcp:10.0.0.1:22"]
  allowExec: [/usr/bin/make, /usr/local/go/bin/**, "@shells", "@git", "@build"]
  denyExec: [/usr/bin/curl]
  groups:
    "@build": [/usr/bin/make, /usr/bin/cc, /usr/local/go/bin/**]
```

- `allowPaths` and `denyPaths` are paths in the container: `/workspace/**`
  and `/workspace` both mean `/workspace` and everything under it. Other
  globs and relative paths are rejected. Deny wins.
- `askPaths`: paths asked about even inside what `allowPaths` allows
  (`--ask-path`), same syntax. The most specific rule decides, an ask
  wins over an allow as specific, and a deny wins over both.
- Also allowed: `/dev/null` and the other harmless devices, the
  terminal (`/dev/tty`, `/dev/pts`) and `/dev/termination-log`.
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
- `allowNet` and `denyNet`: destinations in the `--allow-net`
  syntax; `all` is every destination, unix sockets included. They need
  `connect` in `mediate`. Deny wins. Loopback and unix listeners
  started in the container are allowed without asking.
- `askNet`: destinations asked about even inside what `allowNet`
  allows (`--ask-net`). The most specific rule decides, an ask wins over
  an allow as specific, and a deny wins over both. Needs `network` in
  `mediate`.
- `allowExec` and `denyExec`: programs in the container, like `allowPaths`:
  `/usr/bin/make` is that program, `/opt/tools/**` every program below
  `/opt/tools`. `allowExec` also takes groups of programs, resolved in
  the container: `@shells`, `@coreutils`, `@search`, `@git`, `@busybox`
  (see [Programs](../workstation/usage.md#programs)); for a busybox
  image, `allowExec: ["@busybox"]` lets its shell and applets run. They
  need `exec` in `mediate`. Deny wins. Also allowed, by a fixed rule:
  the container's command (its first argument, looked up in the
  container's `$PATH`), with any arguments, any number of times, also
  through `kubectl exec`. Other programs are asked about, and a prompt
  about a program of a group offers the group. Programs are
  matched by path only: an allowed interpreter runs any code it is given
  (`python3 -c`, `bash -c`), `ld.so /path/to/program` runs a program
  without executing it, a copy of a program under an allowed path runs,
  busybox applets installed as symlinks are all the same program, a
  `binfmt_misc` handler needs an allow in strict mode (it is never
  asked about), and a `memfd` is never allowed for good. See
  [Programs](../workstation/usage.md#programs) for details.
- `groups`: groups of programs of the policy's own, by name: a new
  group (`@build` above), or a replacement for the built-in group of the
  same name. Their programs are paths in the container, as in
  `denyExec`, resolved when the container starts. `allowExec` names
  them, and a prompt about one of their programs offers the group. Names
  are `@`, a lowercase letter, then lowercase letters, digits or `-`.
  They need `exec` in `mediate`.

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
