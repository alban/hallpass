# Install

## Requirements

- Linux 5.9 or later, with seccomp user notification: check `/proc/sys/kernel/seccomp/actions_avail` contains `user_notif`. hallpass uses the `SECCOMP_IOCTL_NOTIF_ID_VALID` ioctl number fixed in 5.9. CI tests 6.1 and later.
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

See [Usage](usage.md) for the default policy, the [CLI reference](reference.md) for the flags, and [Answers and rules](../answers/index.md) for what to answer.
