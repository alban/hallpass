# Install

## Requirements

- Linux with seccomp user notification (5.0+; `SECCOMP_USER_NOTIF_FLAG_CONTINUE` needs 5.5+). Check `/proc/sys/kernel/seccomp/actions_avail` contains `user_notif`.
- arm64 or amd64.
- Desktop prompts: a session D-Bus with an `org.freedesktop.Notifications` service supporting actions (GNOME, KDE, most notification daemons).
- Strict mode has more requirements: see [Strict mode](strict.md#requirements).

## Build

```console
go build ./cmd/hallpass
```

`make` adds the `grpcnotrace` build tag, which leaves gRPC's debug tracing out of the binary (4 MB smaller).

Then run a program, or a shell, from your project:

```console
$ cd ~/src/myproject
$ hallpass -- copilot
```

See [Usage](usage.md) for the flags and the default policy, and [Answers and rules](../answers/index.md) for what to answer.
