# Use cases

The same flags combine into quite different setups. A few common ones:

## Run an agent, ask about the rest (default)

```console
$ hallpass -- copilot
```

The project, a private `$TMPDIR`, the usual devices and the terminal are writable; every other write pauses the agent and asks you. Add `--allow` for the agent's own state, so it is not asked about at each start:

```console
$ hallpass --allow ~/.copilot --allow ~/.cache/copilot -- copilot
```

## Just audit: allow everything, log it

```console
$ hallpass --ask=allow --log=writes.jsonl -- make install
```

Nothing is ever asked or denied, except the always-denied paths (`--deny`, `~/.config/hallpass` and the hallpass binary). Each write is logged with the reason `audit` when it would have been asked, `policy` when the rules allow it anyway:

```json
{"time":"...","pid":60083,"exe":"/usr/bin/dash","syscall":"openat","path":"/home/me/elsewhere","decision":"allow","reason":"audit"}
```

List what would have been asked: `jq -r 'select(.reason=="audit") | .path' writes.jsonl | sort -u`. Add `--no-implicit` (below) to log the project's writes too.

## Check a tool against the paths it declares

A tool, for example an MCP tool provider, declares where it writes. Check that it writes nowhere else:

```console
$ hallpass --no-implicit --allow ~/.cache/mytool --allow /dev/null --log=writes.jsonl -- mytool
```

With `--no-implicit`, only the `--allow` paths are writable: not the working directory, not a `$TMPDIR`, not `/dev/null`. Any other write is an undeclared one: asked about, or, combined with `--ask=deny` or `--ask=allow`, denied or allowed, and logged.

The terminal is off too. Pass `--allow-tty` to keep the session's own terminal writable, since its `/dev/pts/N` cannot be known in advance.

## Unattended: deny what is not allowed

```console
$ hallpass --ask=deny --log=writes.jsonl -- ./ci-step.sh
```

Nobody is there to answer: writes outside the policy fail with `EACCES`, and the log says which.

## Commands that leave processes behind

Daemons, language servers, `nohup` jobs and MCP servers can outlive the command that started them. hallpass supervises them while it runs. To keep supervising them after the command exits, until the last one exits:

```console
$ hallpass --wait=all --log=writes.jsonl -- ./start-services.sh
```

Press Ctrl-] then `s`, or send SIGTERM, to stop early. Needs Linux 5.9.

## Answer from elsewhere

When the agent owns the whole screen, or runs without a terminal:

```console
$ hallpass --ask=answer -- copilot     # in one terminal
$ hallpass answer                      # in another
```

Or `--ask=desktop` for desktop notifications. See [over ssh](usage.md#over-ssh).

## Code you don't trust

Lite mode is about honest mistakes: a deliberately malicious process can race its checks. Strict mode enforces the answers in the kernel on the real file:

```console
$ hallpass --mode=strict -- copilot
```

It asks just like lite mode. See [strict mode](strict.md) for the requirements, and [limitations](../design.md#limitations) for what neither mode covers yet.
