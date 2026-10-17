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

Policy changes apply to containers started afterwards: a running
session keeps the policy it started with.

The syscalls mediated are the same as `hallpass`'s: writes, renames,
links, removals... (see [How it works](../design.md)), and new user and
mount namespaces are refused. The policy is merged into the container's
own seccomp profile (`RuntimeDefault`, `Localhost` or `Unconfined`):
hallpass's rules first, the rest kept.

[deploy/kubernetes/sample.yaml](https://github.com/alban/hallpass/blob/main/deploy/kubernetes/sample.yaml)
has a complete example.
