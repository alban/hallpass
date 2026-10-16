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

## Web UI

`web.mp4` shows a terminal (left) and [`hallpass web`](../docs/usage.md#web-ui-experimental) in a browser (right) side by side. A shell runs under hallpass in [`example/`](example): `make` writes in the project without a question; appending to `~/.bashrc` is asked in both places and denied from the browser, and the terminal prompt goes away; `make install` creates `~/.local/bin`, answered "Always" from the browser, which also covers the copy that follows. The Activity view (filtered on "answered") and the Rules view show the result.

No agent: [`web/record.js`](web/record.js) scripts the whole timeline, so every recording is the same apart from pids and times. It runs one headless Chromium page that frames a [ttyd](https://github.com/tsl0922/ttyd) terminal and `hallpass web` (whose `frame-ancestors`/`X-Frame-Options` headers it drops in that browser only), types the commands, clicks the answers with a drawn pointer and records the page with Puppeteer's screencast; `ffmpeg` then encodes the mp4. The session gets its own `HOME`, `XDG_RUNTIME_DIR` and `XDG_CONFIG_HOME` in a fresh directory, so `hallpass web` only sees this session and the demo commands never write in your home.

### Recording

Requirements: Go, `node` and `npm`, `ttyd`, `ffmpeg` (with libx264), and Chromium (on Ubuntu, `snap install chromium`). The Makefile runs `npm ci` in `web/` to install `puppeteer-core`.

```console
$ make -C demos web.mp4   # build hallpass and record, about 1 minute
```

Variables (`make VAR=value`):

- `CHROMIUM`: the browser, default `/snap/bin/chromium`.
- `CHROMIUM_PROFILE`: a scratch profile, created and removed by the recording. The snap can only write under `~/snap/chromium/common/`, hence the default `~/snap/chromium/common/hallpass-demo-web`; any directory works with a non-snap Chromium.
- `WEB_TMPDIR`: where the run directory (HOME, project, sockets, raw recording) is created with `mktemp`, default `$TMPDIR` or `/tmp`. It is removed after a successful run, kept on failure with a screenshot of the page (`raw.webm.error.png`). Its path shows in the video: keep it short.
