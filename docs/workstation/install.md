# Install

hallpass has no released binaries yet: you build it from source, with Go.

## Requirements

- Linux 5.9 or later, with seccomp user notification: check `/proc/sys/kernel/seccomp/actions_avail` contains `user_notif`. hallpass uses the `SECCOMP_IOCTL_NOTIF_ID_VALID` ioctl number fixed in 5.9. CI tests 6.1 and later.
- arm64 or amd64.
- [Go](https://go.dev/doc/install) 1.26 or later, to build. Nothing else: the BPF programs are prebuilt in the repository, and the binary is static.
- Optional, for desktop prompts: a session D-Bus with an `org.freedesktop.Notifications` service supporting actions (GNOME, KDE, most notification daemons). Without it, hallpass asks in the terminal.
- Optional, strict mode has more requirements: see [Strict mode](strict.md#requirements).

## Build and install

```console
$ go install -tags grpcnotrace github.com/alban/hallpass/cmd/hallpass@main
```

This puts `hallpass` in `$(go env GOPATH)/bin`, usually `~/go/bin`; add it to your `PATH` if it is not there yet:

```console
$ export PATH=$PATH:$(go env GOPATH)/bin
$ hallpass --help
```

The `grpcnotrace` build tag leaves gRPC's debug tracing out of the binary (4 MB smaller); it is optional.

From a clone, to change the code:

```console
$ git clone https://github.com/alban/hallpass
$ cd hallpass
$ make install               # builds ./hallpass and ./hallpass-request, copies them to ~/.local/bin
```

`make install BINDIR=~/bin` installs elsewhere. `hallpass-request` is built with `musl-gcc` (Debian and Ubuntu: `musl-tools`), or with Docker when it is not installed; `make` alone builds only `./hallpass`.

## Run

Run a program, or a shell, from your project:

```console
$ cd ~/src/myproject
$ hallpass -- copilot        # or any command; no command: a shell
```

[Getting started](getting-started.md) walks through a first session. See [Usage](usage.md) for the default policy, the [CLI reference](reference.md) for the flags, and [Answers and rules](../answers/index.md) for what to answer.
