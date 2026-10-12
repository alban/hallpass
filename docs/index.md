# hallpass

**Run an AI coding agent in your shell, and get asked before it writes outside your project.**

```console
$ cd ~/src/myproject
$ hallpass -- copilot        # or: claude, codex, gemini, agy, aider, ... or just `hallpass` for a shell
```

![hallpass denying a shell, then a Makefile run by copilot, writing outside the project](https://raw.githubusercontent.com/alban/hallpass/main/demos/hallpass.gif)

Everything the agent starts (shells, compilers, `git`, `npm`, scripts) inherits the sandbox. Writes inside the project directory go through without asking. Writes anywhere else pause the process and ask you, in a bar drawn over the bottom of your terminal or as a desktop notification.

hallpass is enforced by the kernel, from outside the agent, so it does not depend on the agent being well-behaved. It complements the agent's own permission prompts rather than replacing them.

## Two modes

- **Lite mode** (default, no root) uses [seccomp user notification](design.md#lite-mode-seccomp-user-notification): the kernel pauses filesystem-modifying syscalls and lets hallpass ask you instead of just failing them.
- **Strict mode** (`--mode=strict`, root only to load it) adds [BPF-LSM](design.md#strict-mode-bpf-lsm) enforcement on the real inode, closing symlink races, bind mounts and `io_uring` bypasses.

## Get started

```console
$ go build ./cmd/hallpass
$ ./hallpass -- copilot
```

See [How it works](design.md) for the design, and [Usage](usage.md) for the flags, the default policy and running with agent CLIs.

hallpass is Apache-2.0 licensed. The source is on [GitHub](https://github.com/alban/hallpass).
