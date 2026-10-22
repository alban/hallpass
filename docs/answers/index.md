# Answers and rules

When a write needs a human, the session holds it as a **pending request**: what is written, by which process and its parents, and what each answer would cover. Every client shows the same requests and gives the same answers: the terminal prompt, desktop notifications, `hallpass answer`, the [web UI](web.md), and in [Kubernetes](../kubernetes/answer.md) the `hallpass-node` client and the Headlamp plugin. The first answer wins, and the other clients take their prompt down. See [Where to answer](clients.md) for what each client offers, and [Write a client](api.md) for the API they share.

## Answers

| Key | Answer | Effect |
|---|---|---|
| `o` | once | allow this access only |
| `t` | temp | allow the folder shown for 5 minutes |
| `a` | always | allow the folder shown for the rest of the session |
| `g` | grant | (request made [in advance](../workstation/usage.md#asking-in-advance)) allow what was asked for (a folder, a program, destinations), for the duration asked |
| `d` | deny | deny this access; a retry asks again |
| `n` | never | deny this path for the rest of the session, without asking |
| `Esc` | dismiss | deny this access, remember nothing |

A request with no answer before the timeout (`--timeout`, or the policy's `promptTimeout` in Kubernetes) is dismissed: denied, and asked again on a retry. A request made in advance offers only `grant`, `deny` and `dismiss`; its timeout is reported to the program as `ETIMEDOUT`.

## The folder of temp and always

`temp` and `always` grant a folder, shown in the prompt ("[t] and [a] allow: ~/.cache/thumbs"), not just the file, so the writes that usually follow are not asked one by one:

- under your home, its first component (`~/src`), two for hidden ones (`~/.cache/thumbs`), three under `~/.local` (`~/.local/share/app`);
- elsewhere, the first two components (`/usr/local`, `/etc/apt`).

They are not offered for a file directly in your home or in `/`, nor when the folder would contain your home, a denied path or a flagged secret store (such as `~/.config/gh` under `~/.config`): then answer `once`.

Processes of the sandbox may write each other's `/proc/<pid>` files (agents tune `oom_score_adj`, for example). Writing those of a process outside the sandbox is asked about, and `t`, `a` and `n` then apply to that file for every process with the same command name.

For a network destination (with network [mediated](../workstation/usage.md#network-experimental)), `t`, `a` and `n` cover that destination only: address and port, any protocol (looking up a name connects a UDP socket to each address before the TCP connection: one question for both), or the unix socket.

Rules live as long as the session: nothing is written back to the command line or to the policy. Press Ctrl-] in a terminal session to see them, and [edit them](#editing-rules).

## Editing rules

Every rule of a session can be edited, deleted or added, including those from the command line or the policy: from the [web UI](web.md#editing-rules), the [Headlamp plugin](../kubernetes/answer.md#headlamp-plugin), the Ctrl-] menu (`r`) or `hallpass answer`. A change applies to this session only. Rules are written as `VERDICT KIND VALUE [for DURATION]`. The syntax has no quoting: a rule on a name it cannot write (a file named `**`, a path containing ` for ` or a newline...) can be deleted, not edited.

```
allow write /home/me/src/**       # writing in a tree; without /**, the file only
deny exec /usr/bin/curl for 1h    # running a program, for an hour
ask connect tcp:140.82.112.21:443 # a destination; unix:/run/x.sock, unix:@name, all...
allow proc oom_score_adj chrome   # /proc/<pid>/oom_score_adj of the processes named chrome
deny unknown                      # the paths hallpass could not read (lite mode)
```

Editing gives no more power than answering: an allow rule may only grant what `always` could (a [folder](#the-folder-of-temp-and-always), one program, one destination), or narrow the allow rule it replaces, for no longer, without getting past an ask rule the replaced one did not. Deny and ask rules can be added and removed freely. The built-in denials (`~/.config/hallpass`, the hallpass binary, the session sockets and web UI ports) are not rules you can change. In Kubernetes, a session whose policy does not ask can only be tightened. An edit fails if the rules changed since they were shown: look again and redo it.

```console
$ hallpass answer rules
ID  RULE                           LABEL
1   allow write /home/me/proj/**
...
42  allow write /home/me/.cache/**
$ hallpass answer edit 42 allow write /home/me/.cache/pip/**
$ hallpass answer add deny exec /usr/bin/curl
$ hallpass answer delete 43
```

`hallpass answer [PID] add --label TEXT RULE` labels the rule; an edit keeps the label, except a program group's (`@shells`). An edit is a new rule, with a new ID.

## Prompts that don't flood you

Prompts are designed not to overwhelm you:

- one notification per session, updated in place;
- one question at a time, oldest first; the terminal prompt counts the requests waiting behind it, "(+3 waiting)", and updates the count as they arrive or close;
- **coalescing:** concurrent requests from the same process for the same operation on the same path become one request, and one answer releases them all. Requests from different processes are never merged, because the prompt names one process and your answer must not reach another one you didn't see;
- **settling:** a `temp` or `always` answer adds a rule for the folder the prompt names, and every pending request that rule allows is settled at once, without a question, as if it had arrived after the rule. `once`, `deny` and `never` add no folder rule, so they settle nothing else.

<video src="../assets/demos/coalesce.mp4" poster="../assets/demos/coalesce.png" controls muted playsinline aria-label="eight parallel writes under ~/.cache/thumbs give one prompt; answering always creates all eight files and shows as a rule"></video>

*Eight parallel writes under one folder: one question, and "always" settles all eight.*
