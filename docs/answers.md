# Answers and rules

The same answers apply everywhere: the terminal prompt, desktop notifications, `hallpass answer`, the [web UI](web.md), and in [Kubernetes](kubernetes/answer.md) the `hallpass-node` client and the Headlamp plugin.

## The prompt

In a terminal, hallpass asks in a bar drawn over the bottom of the screen, like a tmux status line:

```
 hallpass: node (pid 41237) wants to write
 /home/me/.npm/_cacache/tmp/x
 by: npm install ← bash ← copilot
 [t] and [a] allow: /home/me/.npm/_cacache
 [o] allow once  [t] for 5m0s  [a] always  [d] deny  [n] never  [Esc] dismiss
```

The `by:` line shows the command line of the process and the commands it was started from. The process can change both, so they help you understand the request but prove nothing.

The program runs on a pseudo-terminal that hallpass relays, so it cannot see or answer the question. Its output, and that of its background jobs, keeps showing above the bar, and when you answer, your terminal ends up exactly as if the bar had never been there. Keys typed in the first half second are ignored, so typing meant for the program does not answer by accident.

Without a terminal, hallpass asks with a desktop notification. It has room for three buttons only: Allow once, Allow 5 min and Deny (or Allow once, Deny and Never when there is no folder to offer).

## Answers

| Key | Answer | Effect |
|---|---|---|
| `o` | once | allow this access only |
| `t` | temp | allow the folder shown for 5 minutes |
| `a` | always | allow the folder shown for the rest of the session |
| `d` | deny | deny this access; a retry asks again |
| `n` | never | deny this path for the rest of the session, without asking |
| `Esc` | dismiss | deny this access, remember nothing |

A request with no answer before the timeout (`--timeout`, or the policy's `askTimeout` in Kubernetes) is dismissed: denied, and asked again on a retry.

## The folder of temp and always

`temp` and `always` grant a folder, shown in the prompt ("[t] and [a] allow: ~/.cache/thumbs"), not just the file, so the writes that usually follow are not asked one by one:

- under your home, its first component (`~/src`), two for hidden ones (`~/.cache/thumbs`), three under `~/.local` (`~/.local/share/app`);
- elsewhere, the first two components (`/usr/local`, `/etc/apt`).

They are not offered for a file directly in your home or in `/`, nor when the folder would contain your home, a denied path or a flagged secret store (such as `~/.config/gh` under `~/.config`): then answer `once`.

Processes of the sandbox may write each other's `/proc/<pid>` files (agents tune `oom_score_adj`, for example). Writing those of a process outside the sandbox is asked about, and `t`, `a` and `n` then apply to that file for every process with the same command name.

Rules live as long as the session: nothing is written back to the command line or to the policy. Press Ctrl-] in a terminal session to see them; the web UI can remove them.

## Prompts that don't flood you

Prompts are designed not to overwhelm you:

- one notification per session, updated in place;
- one question at a time, oldest first; the terminal prompt counts the requests waiting behind it, "(+3 waiting)", and updates the count as they arrive or close;
- **coalescing:** concurrent requests from the same process for the same operation on the same path become one request, and one answer releases them all. Requests from different processes are never merged, because the prompt names one process and your answer must not reach another one you didn't see;
- **settling:** a `temp` or `always` answer adds a rule for the folder the prompt names, and every pending request that rule allows is settled at once, without a question, as if it had arrived after the rule. `once`, `deny` and `never` add no folder rule, so they settle nothing else.

<video src="../assets/demos/coalesce.mp4" poster="../assets/demos/coalesce.png" controls muted playsinline aria-label="eight parallel writes under ~/.cache/thumbs give one prompt; answering always creates all eight files and shows as a rule"></video>

*Eight parallel writes under one folder: one question, and "always" settles all eight.*

The prompt shows the target path and, as a `by:` line, the command that tried the write and its parent chain (for example `cp hello ~/.local/bin/hello ← make ← copilot`), so you can see who is really behind the access.

Every client answers the same requests: the first answer wins, and the others take their prompt down.
