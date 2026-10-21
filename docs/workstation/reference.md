# CLI reference

```
hallpass [flags] [--] [command [args...]]     # default command: $SHELL
```

`hallpass --help` lists the same flags, in the same order, with their defaults.

## Sandbox

```
      --mode MODE          lite (default, no root) | strict (BPF-LSM enforcement)
      --mediate LIST       mediated syscall categories: files, exec, network (default files,exec; network is experimental)
      --escalate TOOL      strict mode as a regular user: how to run the loader as root:
                           auto | ask | pkexec | sudo | run0 | doas | su | manual | none
                           (default: saved choice, else ask on a terminal, else auto)
      --allow-userns       let the sandbox create user/mount namespaces (weakens lite mode; always on in strict mode)
      --no-implicit        only --allow-path paths are writable and --allow-exec programs run: no project dir, $TMPDIR, devices, terminal or implicit program groups
```

## Files

```
  -C, --workdir DIR        project dir, writable without asking (default: cwd)
      --allow-path PATH    also writable without asking (repeatable)
      --deny-path PATH     always denied (repeatable, wins over --allow-path)
      --ask-path PATH      asked about, even inside what --allow-path allows (repeatable)
      --allow-tty          the session's own terminal is writable (default true; off with --no-implicit unless given)
```

The paths cover everything below them; a relative path is relative to the current directory. The most specific rule decides, an ask wins over an allow as specific, and `--deny-path` wins over both. See [Default policy](usage.md#default-policy).

## Programs

```
      --allow-exec PROG    program run without asking (repeatable, comma-separated): a name looked up in $PATH, a path, DIR/** for every program below DIR,
                           or a group: @shells, @coreutils, @search, @git, @busybox
      --deny-exec PROG     program never run (repeatable, comma-separated, no groups, wins over --allow-exec)
      --group @NAME=PROG,...  a group of programs of your own, or a replacement for the built-in group of that name (repeatable)
```

See [Programs](usage.md#programs).

## Network (experimental)

```
      --allow-net DEST     network destination allowed without asking (repeatable; needs network in --mediate)
      --deny-net DEST      network destination always denied (repeatable, wins over --allow-net)
      --ask-net DEST       network destination asked about, even inside what --allow-net allows (repeatable)
```

See [Network](usage.md#network-experimental).

## Prompts

```
      --prompt MODE        auto | term | desktop | answer | deny | allow   (default: auto = term if on a terminal, else desktop, else answer;
                           allow = audit: allow everything, log it with --log)
      --timeout DUR        unanswered prompt is denied after DUR (default 30s; 0 = wait forever)
```

See [Where to answer](../answers/clients.md); `--prompt=deny` and `--prompt=allow` answer every request without asking (see [use cases](use-cases.md)).

## Session

```
      --log FILE           append one JSON line per mediated syscall to FILE
      --wait WHAT          main (default): exit with the command | all: keep supervising its background processes (Linux 5.9+)
```

## Subcommands

```
hallpass policy [flags]                       # print the rules these flags give, then exit
hallpass answer [PID]                         # answer another session's prompts from this terminal
hallpass answer [PID] rules                   # list the session's rules
hallpass answer [PID] add [--label TEXT] RULE # add a rule, e.g. deny exec /usr/bin/curl for 1h
hallpass answer [PID] edit ID RULE            # replace rule ID
hallpass answer [PID] delete ID...            # remove rules
hallpass web [--listen ADDR] [--open] [--node ADDR]  # follow and answer every session in a browser (experimental)
```
