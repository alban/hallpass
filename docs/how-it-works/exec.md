# Programs

With `exec` in `--mediate` (the default, also in a [HallpassPolicy](../kubernetes/policies.md)), running a program is mediated like a write: a program no rule allows is asked about. The command given to hallpass and the implicit groups of common programs (`@shells`, `@coreutils`, `@search`, `@git`; not in a HallpassPolicy, and off with `--no-implicit`) are allowed by default; other groups (`@busybox`, or groups of your own, `--group` or a policy's `groups`) are allowed by name, or from a prompt about one of their programs. See [Programs](../workstation/usage.md#programs) for the rules and answers.

Exec rules are about which programs start, not what they do: an allowed interpreter runs any code it is given (`python3 -c`, `bash -c`, `node -e`), the dynamic loader runs any program it is given (`ld.so /path/to/program`), and a copy of a program under an allowed path runs. They make an agent's use of an unexpected tool visible, they do not contain it. Rules on the arguments are planned.

## Lite mode

Syscalls paused: `execve` and `execveat`. They are paused whatever `--mediate` says (strict mode needs them to add new processes to the session), and the program is only checked with `exec` mediated.

What the supervisor reads:

- The path, from `/proc/<pid>/mem`, resolved like a write's: symlinks followed, in the process's root and working directory.
- The `#!` line of a script, from the file, and of its interpreter, as the kernel does (up to 4 interpreters deep): the script and each interpreter must be allowed.

A denied exec fails with `EACCES`. A path that is not an executable file is let through: the kernel fails it, as when a shell tries each `$PATH` directory. A program run from a file descriptor (`execveat` with `AT_EMPTY_PATH`) has no path: it is asked about as an unknown path, "once" only.

TOCTOU: exposed. The path is read from memory and the files are looked up before the kernel runs the exec, which can then find another file.

## Strict mode

In strict mode, the supervisor first adds the thread calling `execve` to the session (the `members` map), before the new program runs. With `exec` mediated, the same syscalls are asked about, then the LSM hook checks the files the kernel executes:

| Hook | Checks |
|---|---|
| `bprm_check_security` | the file the kernel is about to execute: the program, then each `#!` interpreter or `binfmt_misc` handler |

The rule is matched on that file, whatever path, symlink or bind mount reached it, with the same walk as for [files](files.md#strict-mode), so swapping the path after the check does not help. A file with no path at all (a `memfd`) is always denied. The question is still asked at seccomp time; a "once" answer becomes a one-shot grant for the files of that `execve`. When the supervisor cannot see the program (unreadable path, or a process in another mount namespace), it lets the exec continue and the kernel's rules decide, without asking.

Maps:

| Map | Key → value | Relation | Written by |
|---|---|---|---|
| `rules` | as for files, with allow and deny for executing the programs at that path (no ask) | one entry per path component | the supervisor |
| `grants` | thread → the nodes of the program and its interpreters, for a "once" answer (up to 8) | 1:1, per thread | the supervisor, before continuing; deleted when the syscall returns |
| `members` | task → its session | 1:1, per task | the supervisor, at each `execve`; the BPF program, for the tasks a member creates |

TOCTOU: closed: the hook runs on the file the kernel opened to execute.

See [Limitations](limitations.md#programs).
