# Getting started

A first session, in a throwaway directory, to see what hallpass asks and what your answers do. No AI agent needed: a shell is enough. [Install](install.md) hallpass first.

## Start a sandboxed shell

```console
$ mkdir -p ~/hallpass-tutorial/project
$ cd ~/hallpass-tutorial/project
$ hallpass
hallpass: sandbox started (lite, session 4242). Ctrl-] for the menu, then w for the web UI; 'hallpass web' in another terminal for all sessions.
```

You are in your usual shell, and everything you start from it is in the sandbox. The current directory is the project.

## A write in the project

```console
$ echo hello > notes.txt
```

Nothing is asked: the project is writable.

## A write outside, denied

```console
$ echo hello > ../outside.txt
```

The shell pauses, and a prompt appears at the bottom of the terminal:

```
 hallpass: bash (pid 4250) wants to write
 /home/you/hallpass-tutorial/outside.txt
 by: bash
 [t] and [a] allow: /home/you/hallpass-tutorial
 [o] allow once  [t] for 5m0s  [a] always  [d] deny  [n] never  [w] web UI  [Esc] dismiss
```

Press `d`. The write fails as if the file were not writable:

```console
bash: ../outside.txt: Permission denied
```

`deny` remembers nothing: run the command again and you are asked again.

## A write outside, allowed

Run it again and press `a` (always). The write goes through, and so do the next ones in `~/hallpass-tutorial`, the folder the prompt showed: "always" allows that folder, not just the file.

```console
$ echo hello > ../outside.txt
$ echo again > ../other.txt     # no question this time
```

"Always" lasts until the session ends. Nothing is written to a configuration file: the next `hallpass` asks again.

## See the rules

Press Ctrl-]. An overlay lists the session's rules: the project, the defaults, and the answer you just gave. Press any key to close it.

## Finish

```console
$ exit
$ rm -r ~/hallpass-tutorial
```

Next: run an agent the same way (`hallpass -- copilot`), read [Answers and rules](../answers/index.md) for every answer and what it covers, and [Usage](usage.md) for the default policy and the programs run without asking. A desktop notification or the [web UI](../answers/web.md) can answer instead of the terminal.
