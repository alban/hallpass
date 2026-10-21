# Where to answer

All clients answer the same requests with the same [answers](index.md); they differ in what they show and in what else they let you do.

| Client | Where | Answers | Also |
|---|---|---|---|
| Terminal prompt | the session's terminal | all | Ctrl-] shows and edits the rules; Ctrl-] or a prompt's `w` opens the web UI |
| Desktop notification | without a terminal (`--prompt=desktop`) | three buttons | Open web UI button |
| `hallpass answer` | another terminal | all | list and edit rules |
| [Web UI](web.md) | a browser, every session of the user | all | activity, edit rules |
| `hallpass-node` client | [Kubernetes](../kubernetes/answer.md), one node | all | |
| `hallpass web --node` | [Kubernetes](../kubernetes/answer.md), one node | all | activity, edit rules |
| Headlamp plugin | [Kubernetes](../kubernetes/answer.md#headlamp-plugin), the whole cluster | all | badge, per-pod view and rules, sandbox a workload |

## Terminal prompt

In a terminal, hallpass asks in a bar drawn over the bottom of the screen, like a tmux status line:

```
 hallpass: node (pid 41237) wants to write
 /home/me/.npm/_cacache/tmp/x
 by: npm install ← bash ← copilot
 [t] and [a] allow: /home/me/.npm/_cacache
 [o] allow once  [t] for 5m0s  [a] always  [d] deny  [n] never  [w] web UI  [Esc] dismiss
```

The `by:` line shows the command line of the process and the commands it was started from. The process can change both, so they help you understand the request but prove nothing.

In a desktop session, `[w]` opens the session's [web UI](web.md#from-a-session) and keeps the question: the pairing confirmation shows in its place, then the question comes back, answerable here or in the page.

The program runs on a pseudo-terminal that hallpass relays, so it cannot see or answer the question. Its output, and that of its background jobs, keeps showing above the bar, and when you answer, your terminal ends up exactly as if the bar had never been there. Keys typed in the first half second are ignored, so typing meant for the program does not answer by accident.

## Desktop notification

Without a terminal, hallpass asks with a desktop notification. It has room for three buttons only: Allow once, Deny and Open web UI. The button opens the session's [web UI](web.md#from-a-session), which offers all answers; the notification stays. A request made [in advance](../workstation/usage.md#asking-in-advance) shows the folder, the duration and the program's reason, with Grant, Deny and Open web UI. While the page has the focus, requests show there only; their notification comes back when you switch to another window or tab, or close the page.

## Another terminal

`hallpass answer [PID]` shows the pending requests of a session and takes the same answers as the terminal prompt. `hallpass answer [PID] rules`, `add`, `edit` and `delete` [edit its rules](index.md#editing-rules). See [Usage: over ssh](../workstation/usage.md#over-ssh).
