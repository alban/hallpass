# hallpass

**Run a program in your shell, and get asked before it writes outside your project.**

hallpass was built for AI coding agents, and is useful for any program you don't fully trust.

```console
$ cd ~/src/myproject
$ hallpass -- copilot        # or: claude, codex, gemini, agy, aider, ... or just `hallpass` for a shell
```

<video src="assets/demos/shell.mp4" poster="assets/demos/shell.png" controls muted playsinline aria-label="a shell under hallpass: a write in the project goes through, a write to ~/.bashrc is asked and denied, Ctrl-] shows the rules"></video>

*A write in the project goes through; appending to `~/.bashrc` pauses the shell until you answer.*

Everything the program starts (shells, compilers, `git`, `npm`, scripts) inherits the sandbox. Writes inside the project directory go through without asking. Writes anywhere else pause the process and ask you, in a bar drawn over the bottom of your terminal or as a desktop notification.

hallpass is enforced by the kernel, from outside the program, so it does not depend on the program being well-behaved. With an AI agent, it complements the agent's own permission prompts rather than replacing them.

<video src="assets/demos/copilot.mp4" poster="assets/demos/copilot.png" controls muted playsinline aria-label="copilot --yolo under hallpass: its install step wants to copy a binary into ~/.local/bin, hallpass asks and the write is denied"></video>

*`copilot --yolo` skips its own permission prompts, but its `make install` into `~/.local/bin` is still asked, by the `cp` that makes the write.*

## What for

- **AI coding agents** (copilot, claude, codex, ...): they run commands on your behalf, sometimes in the wrong place.
- **Installers and package hooks**: `curl | sh`, `npm install` or `pip install` running scripts you have not read.
- **Unfamiliar builds and tools**: a project's `make install`, a tool you try for the first time.
- **Audit**: see every file a program writes (`--prompt=allow --log`), or check it against the paths it declares.

See [Use cases](workstation/use-cases.md) for the flags of each.

## Two modes

- **Lite mode** (default, no root) uses [seccomp user notification](design.md#lite-mode-seccomp-user-notification): the kernel pauses filesystem-modifying syscalls and lets hallpass ask you instead of just failing them.
- **Strict mode** (`--mode=strict`, root only to load it) still pauses writes and asks you interactively like lite mode, and adds [BPF-LSM](design.md#strict-mode-bpf-lsm) enforcement on the real inode, closing the TOCTOU race that lite mode is inherently exposed to (symlink races, bind mounts, other mount namespaces).

## Get started

```console
$ go build ./cmd/hallpass
$ ./hallpass -- copilot
```

See [Install](workstation/install.md) to build it, [Usage](workstation/usage.md) for the default policy and running with agent CLIs, the [CLI reference](workstation/reference.md) for the flags, [Answers and rules](answers/index.md) for what to answer, and [Use cases](workstation/use-cases.md) for auditing, checking a tool's declared paths, CI and more. To sandbox pods, see [Kubernetes](kubernetes/index.md). [How it works](design.md) explains the design and its limitations.

The user-space code is Apache-2.0 licensed; the BPF programs are GPL-2.0-only OR BSD-2-Clause. The source is on [GitHub](https://github.com/alban/hallpass).
