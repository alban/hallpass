# Demos

`hallpass.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs) from `hallpass.tape`. It shows two scenarios:

1. A shell in the sandbox: writing in the project goes through, appending to `~/.bashrc` is asked and denied, and Ctrl-] shows the session's rules.
2. `copilot --yolo` asked to "Build the project" in [`example/`](example), whose Makefile appends to `~/.bashrc`. hallpass shows the command and who started it; the write is denied, and copilot reports the bad line.

The Makefile only appends a comment, so a demo gone wrong does no harm.

## Recording

Requirements: `vhs` (with `ttyd`, `ffmpeg` and a Chromium; on arm64 Linux, `snap install chromium`), and `copilot`, logged in.

The tape copies `example/` to `/tmp/hallpass-demo`, outside any git repository, so that copilot works on it alone. Copilot asks whether to trust a new folder, which the tape does not answer: trust it once beforehand.

```console
$ cp -r demos/example /tmp/hallpass-demo && (cd /tmp/hallpass-demo && copilot)   # trust the folder, then /exit
$ go build -o hallpass ./cmd/hallpass
$ vhs demos/hallpass.tape
```

The agent's answers vary from run to run: check the result before committing it.
