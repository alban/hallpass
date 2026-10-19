# hallpass

**Run a program in your shell, and get asked before it writes outside your project.**

hallpass was built for AI coding agents, and is useful for any program you don't fully trust.

```console
$ cd ~/src/myproject
$ hallpass -- copilot        # or: claude, codex, gemini, agy, aider, ... or just `hallpass` for a shell
```

<video src="assets/demos/shell.mp4" poster="assets/demos/shell.png" controls muted playsinline aria-label="a shell under hallpass: a write in the project goes through, a write to ~/.bashrc is asked and denied, Ctrl-] shows the rules"></video>

*A write in the project goes through; appending to `~/.bashrc` pauses the shell until you answer.*

Everything the program starts (shells, compilers, `git`, `npm`, scripts) inherits the sandbox. Writes inside the project directory go through without asking. Writes anywhere else, and programs outside the common ones, pause the process and ask you, in a bar drawn over the bottom of your terminal, as a desktop notification or in a web UI.

!!! warning "A proof of concept"
    hallpass catches **honest mistakes**: a wrong path, an overeager install script, a command run in the wrong directory. It does not contain a hostile program yet. Reads are not restricted, so a program can read your secrets; the network is not mediated by default; and a process can ask a service outside the sandbox (`systemd-run`, a container daemon) to write for it. Strict mode closes the races of lite mode, not these gaps. See the [security model](how-it-works/index.md#security-model) and the [limitations](how-it-works/limitations.md).

## Get started

hallpass runs on Linux 5.9 or later (arm64, amd64) and builds with Go:

```console
$ go install github.com/alban/hallpass/cmd/hallpass@main
$ hallpass -- copilot
```

[Install](workstation/install.md) has the details, and [Getting started](workstation/getting-started.md) walks through a first session in a throwaway directory. To sandbox pods, see [Kubernetes](kubernetes/index.md).

## With an AI agent

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

- **Lite mode** (default, no root) uses [seccomp user notification](how-it-works/lite.md): the kernel pauses filesystem-modifying syscalls and lets hallpass ask you instead of just failing them.
- **Strict mode** (`--mode=strict`, root only to load it) still pauses writes and asks you interactively like lite mode, and adds [BPF-LSM](how-it-works/strict.md) enforcement on the real inode, closing the TOCTOU race that lite mode is inherently exposed to (symlink races, bind mounts, other mount namespaces).

## Documentation

[Usage](workstation/usage.md) covers the default policy and running with agent CLIs, the [CLI reference](workstation/reference.md) the flags, [Answers and rules](answers/index.md) what to answer, and [Use cases](workstation/use-cases.md) auditing, checking a tool's declared paths, CI and more. [How it works](how-it-works/index.md) explains the design and its limitations, and [Comparison](comparison.md) how hallpass relates to other tools.

The user-space code is Apache-2.0 licensed; the BPF programs are GPL-2.0-only OR BSD-2-Clause. The source is on [GitHub](https://github.com/alban/hallpass).
