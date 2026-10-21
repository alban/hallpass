# Write a client

Every client on the [previous page](clients.md) except the terminal prompt and the desktop notification uses the same gRPC API, defined in [`api/session/v1/session.proto`](https://github.com/alban/hallpass/blob/main/api/session/v1/session.proto). You can write your own: a different UI, a bot that answers some requests, a logger.

!!! warning
    Experimental: the goal is a stable API for clients outside this repository, but it may still change incompatibly. Clients built from the same commit as hallpass always work.

## Where it is served

- **On a workstation**, each session serves its own unix socket, `$XDG_RUNTIME_DIR/hallpass/<pid>.sock` (without `XDG_RUNTIME_DIR`, `hallpass-<uid>/<pid>.sock` in `$TMPDIR` or `/tmp`, in a directory that must be the user's, mode 0700), where `<pid>` is the supervisor's. It accepts only clients of the same user that are not themselves sandboxed (it refuses any process running under a seccomp filter), so a sandboxed program cannot answer its own requests. A client should check the other way round too, that the socket is served by that pid and not by a fake from the sandbox; the Go clients in this repository do.
- **In Kubernetes**, the `hallpass-node` agent serves every session of its node on port 7323, reached through `kubectl port-forward` (see [who can answer](../kubernetes/answer.md#who-can-answer)). `List` returns the sessions; the other calls select one with the `hallpass-session` gRPC metadata, set to a `SessionInfo.id`.

## Calls

| Call | What it does |
|---|---|
| `Info`, `List` | describe the session, or the sessions served |
| `Snapshot` | the pending requests and the rules |
| `Events` | a stream of requests opened and closed, rule changes, and with `decided` every decided access; with `snapshot`, the first batch carries a snapshot taken after subscribing, so no event is lost in between |
| `Answer` | answer a pending request like the terminal prompt: `once`, `temp`, `always`, `deny` or `never`, with the session's own scope (`Prompt.scope`); `grant`, `deny` or `dismiss` for a request made in advance |
| `Apply` | the lower level: allow or deny requests, add and remove rules of your own scope, all at once, optionally only if the rules have not changed since a given generation |

A request carries what the prompt shows (`Prompt`: operation, path, command line, parents, the scope of `temp` and `always`, a secret-store warning) and the raw data behind it (`Object`, `Subject`, `Fact`). The process controls its command line and parents: they help a human but prove nothing, so do not base automatic answers on them alone.

A request made [in advance](../workstation/usage.md#asking-in-advance) has `Request.advance` set (whether the path is a folder, the duration asked, the program's reason, the destinations `dest` of a `connect` request, and `writable` when the program or folder of an `exec` request may be written without a prompt) and, in its `Prompt`, `advance`, `grant_for` and `reason`; `Prompt.op` is `write`, `exec` or `connect to`, and `Prompt.path` ends in `/**` for a folder, or names the destinations. The reason is the program's own words: show it as such. Answering `grant` adds an allow rule for that path or those destinations, in the rule set `advance`, expiring after `grant_for` (never, when it is zero). A request denied because nobody answered in time closes with `Decision.timed_out`. When the program gives a grant back, the rules are removed and an `Event.released` names them and the program.

## Example

With [grpcurl](https://github.com/fullstorydev/grpcurl), from a checkout of the repository:

```console
$ S=$XDG_RUNTIME_DIR/hallpass/205382.sock
$ grpcurl -plaintext -unix -import-path api/session/v1 -proto session.proto \
    $S hallpass.session.v1.Session/Snapshot
{
  "pending": [
    {
      "id": "1",
      "syscall": "openat",
      ...
      "prompt": {
        "op": "write",
        "path": "/home/me/notes.txt",
        ...
$ grpcurl -plaintext -unix -import-path api/session/v1 -proto session.proto \
    -d '{"request": 1, "answer": "once", "client": "grpcurl"}' \
    $S hallpass.session.v1.Session/Answer
{}
```

The `client` name shows in the activity and, in Kubernetes, in the pod's Events.

In Go, import `github.com/alban/hallpass/api/session/v1` (package `sessionpb`).
