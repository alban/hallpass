# Demos

`hallpass.gif` is recorded with [VHS](https://github.com/charmbracelet/vhs) from `hallpass.tape`. It shows two scenarios:

1. A shell in the sandbox: writing in the project goes through, appending to `~/.bashrc` is asked and denied, and Ctrl-] shows the session's rules.
2. `copilot --yolo` asked to "Build and install the project" in [`example/`](example). The `install` step copies the built binary into `~/.local/bin`, outside the project, so hallpass asks and the write is denied. A fast model (`--model claude-haiku-4.5`) keeps the agent's turn short.

Title cards and `#` comments typed in the shell explain each step.

## Recording

Requirements: `vhs` (with `ttyd`, `ffmpeg` and a Chromium; on arm64 Linux, `snap install chromium`), and `copilot`, logged in.

The tape copies `example/` to `/tmp/hallpass-demo`, outside any git repository, so that copilot works on it alone. Copilot asks whether to trust a new folder, which the tape does not answer: trust it once beforehand.

```console
$ cp -r demos/example /tmp/hallpass-demo && (cd /tmp/hallpass-demo && copilot)   # trust the folder, then /exit
$ make -C demos validate       # check the tape
$ make -C demos hallpass.gif   # build hallpass and record, about 2 minutes
```

`vhs` is looked up in `$PATH` (`go install` puts it in `~/go/bin`); override with `make VHS=/path/to/vhs`. The agent's answers vary from run to run: check the result before committing it.
