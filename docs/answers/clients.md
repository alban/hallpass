# Where to answer

All clients answer the same requests with the same [answers](index.md); they differ in what they show and in what else they let you do.

| Client | Where | Answers | Also |
|---|---|---|---|
| Terminal prompt | the session's terminal | all | Ctrl-] shows the rules |
| Desktop notification | without a terminal (`--ask=desktop`) | three buttons | |
| `hallpass answer` | another terminal | all | |
| [Web UI](web.md) | a browser, every session of the user | all | activity, remove rules |
| `hallpass-node` client | [Kubernetes](../kubernetes/answer.md), one node | all | |
| `hallpass web --node` | [Kubernetes](../kubernetes/answer.md), one node | all | activity, remove rules |
| Headlamp plugin | [Kubernetes](../kubernetes/answer.md#headlamp-plugin), the whole cluster | all | badge, per-pod view, sandbox a workload |

## Terminal prompt

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

## Desktop notification

Without a terminal, hallpass asks with a desktop notification. It has room for three buttons only: Allow once, Allow 5 min and Deny (or Allow once, Deny and Never when there is no folder to offer). A request made [in advance](../workstation/usage.md#asking-in-advance) shows the folder, the duration and the program's reason, with Grant and Deny.

## Another terminal

`hallpass answer [PID]` shows the pending requests of a session and takes the same answers as the terminal prompt. See [Usage: over ssh](../workstation/usage.md#over-ssh).
