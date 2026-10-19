# Strict mode

Strict mode builds on lite mode: it still pauses writes and asks you interactively, exactly as lite mode does, and the workload waits for your answer. The BPF-LSM program is an added layer, not a replacement: it enforces each answer in the kernel on the real file. It is not a silent, pre-configured policy.

Strict mode enforces your answers in the kernel with a BPF-LSM program, on the real file the kernel is about to modify. This closes the TOCTOU race that lite mode cannot: with seccomp, the kernel re-resolves the path after the check, so a malicious multi-threaded process can swap it in between (via a symlink, bind mount or rename). The LSM hook runs after that resolution, so there is no window to race. See [How it works](../design.md#strict-mode-bpf-lsm).

"Allow once" in strict mode allows exactly the paused syscall: the kernel grants it to that thread only, and drops the grant when the syscall returns. Another thread, or a retry of the same write later, is asked again. Dropping the grant needs a `sys_exit` tracepoint, which slows down every syscall on the host a little (about 200 ns) while strict mode runs.

Rules that ask about something inside what is allowed (`--ask-net`, or an ask rule added from a client) work as in lite mode: the kernel denies the asked file or destination unless a more specific allow rule or your "once" answer allows it, so the allow around it does not leak through.

## Requirements

BPF-LSM active, i.e. `bpf` listed in `/sys/kernel/security/lsm`. Fedora enables it by default; Ubuntu builds it but does not activate it (add `bpf` to the `lsm=` kernel parameter). The programs also need the `bpf_path_d_path` kfunc (upstream 6.12; they also use `bpf_preempt_disable` from 6.10); the verifier rejects them otherwise. CI tests 6.12, 6.18 and 7.2.

## Running it

Run hallpass as your user; only loading the BPF programs needs root:

```console
hallpass --mode=strict -- copilot
```

hallpass starts a short-lived copy of itself as root (`--escalate`: `auto` picks pkexec in a graphical session, else sudo, run0 or doas; `manual` prints the command for you to run as root and waits for Enter). Without `--escalate`, hallpass uses the choice saved in `~/.config/hallpass/config` (`escalate = sudo`), or else asks on the terminal which tool to use and whether to remember it; `--escalate=ask` asks again. The config directory is `$XDG_CONFIG_HOME/hallpass` when that variable is set to an absolute path, otherwise `~/.config/hallpass`. The sandbox can never write it. The helper checks it was started for a hallpass of the invoking user, loads and attaches the programs, hands their file descriptors back to the supervisor and exits. The supervisor makes itself non-dumpable, and the LSM denies signals from the sandbox to it.

See [Limitations](../design.md#strict-mode) for what strict mode does not cover.
