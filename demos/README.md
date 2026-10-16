# Demos

Each demo is a directory with its recording script. The [Makefile](Makefile) finds them, encodes every recording the same way into `media/NAME.mp4` and takes a poster frame into `media/NAME.png`. The README shows the posters; the [documentation](../docs/index.md) plays the videos (`docs/assets/demos` links to `media/`).

| Demo | Source | Shown in | Recorded with |
|------|--------|----------|---------------|
| Shell | [`shell/demo.tape`](shell/demo.tape) | README, home page | [VHS](https://github.com/charmbracelet/vhs) |
| Copilot | [`copilot/demo.tape`](copilot/demo.tape) | home page | VHS, with copilot |
| Coalesce | [`coalesce/demo.tape`](coalesce/demo.tape) | How it works | VHS |
| Strict | [`strict/demo.tape`](strict/demo.tape) | How it works | VHS, over ssh |
| Web UI | [`web/record.js`](web/record.js) | Usage | Puppeteer |

[`example/`](example) is a small C project that the demos work in.

```console
$ make -C demos list       # list the demos and their outputs
$ make -C demos web        # build hallpass and record one demo
$ make -C demos all        # record every demo
$ make -C demos posters    # take the posters again, without recording
$ make -C demos validate   # check the tapes' syntax
```

Every run records again: a demo shows the current hallpass. Some vary from run to run (an agent's answers, pids, times): check the result before committing it.

## Adding a demo

Create `NAME/demo.tape` for a terminal demo or `NAME/record.js` for a browser demo, then `make -C demos NAME`. Both record a raw webm in a fresh directory, which the Makefile encodes with `ffmpeg`.

- A tape runs from the repository root, with `./hallpass` built, and gets the fresh directory as `$DEMO_DIR`: use it as `HOME` for anything the demo writes outside its project. The Makefile sets the output with `vhs -o`: leave out the `Output` line.
- A browser script gets its settings from the environment: `HALLPASS` (the binary), `CHROMIUM`, `PROFILE` (a scratch Chromium profile), `WORKDIR` (the fresh directory) and `OUT` (the webm to write). [`web/record.js`](web/record.js) is the model to copy.
- `NAME/poster-at` holds the second the poster is taken from (default 1): pick a frame that tells what the demo is about.

Then show it in the documentation, the paths relative to the page's URL, with a one-line caption saying what to watch for:

```html
<video src="assets/demos/NAME.mp4" poster="assets/demos/NAME.png" controls muted playsinline></video>

*What to watch for.*
```

## Terminal demos

Requirements: `vhs` (with `ttyd` and a Chromium; on arm64 Linux, `snap install chromium`) and `ffmpeg` (with libx264). Title cards and `#` comments typed in the shell explain each step.

- `shell.mp4` (no agent, the same at every run apart from pids): a shell in the sandbox. Writing in the project goes through, appending to `~/.bashrc` is asked and denied, and Ctrl-] shows the session's rules.
- `coalesce.mp4` (no agent): eight parallel `touch` under one folder outside the project give one prompt; "always" allows the folder, settles all eight, and shows as a rule. It runs with `HOME` in `$DEMO_DIR`.
- `strict.mp4` (no agent): [`strict/race`](strict/race/main.go) opens a path while another thread flips one of its bytes, between `./.bashrc` in the project and `../.bashrc`, which is `~/.bashrc`. Under lite mode it soon writes to `~/.bashrc`; under strict mode it never does. Strict mode needs BPF-LSM, so the tape builds `race`, copies it and `hallpass` to `~/tmp/hallpass-demo-strict` on `$STRICT_HOST` (default `fedora`) and runs there over ssh, with `HOME` in that directory. The host needs `bpf` in `/sys/kernel/security/lsm`, Linux 6.12 or later, passwordless sudo, and this host's architecture. The try count varies from run to run.
- `copilot.mp4`: `copilot --yolo` asked to "Build and install the project" in [`example/`](example). The `install` step copies the built binary into `~/.local/bin`, outside the project, so hallpass asks and the write is denied. A fast model (`--model claude-haiku-4.5`) keeps the agent's turn short. The agent's answers vary from run to run.

The copilot demo needs `copilot`, logged in. Its tape copies `example/` to `/tmp/hallpass-demo`, outside any git repository, so that copilot works on it alone. Copilot asks whether to trust a new folder, which the tape does not answer: trust it once beforehand.

```console
$ cp -r demos/example /tmp/hallpass-demo && (cd /tmp/hallpass-demo && copilot)   # trust the folder, then /exit
$ make -C demos copilot   # about 2 minutes
```

## Web UI

`web.mp4` shows a terminal (left) and [`hallpass web`](../docs/usage.md#web-ui-experimental) in a browser (right) side by side. A shell runs under hallpass in [`example/`](example): `make` writes in the project without a question; appending to `~/.bashrc` is asked in both places and denied from the browser, and the terminal prompt goes away; `make install` creates `~/.local/bin`, answered "Always" from the browser, which also covers the copy that follows. The Activity view (filtered on "answered") and the Rules view show the result.

No agent: [`web/record.js`](web/record.js) scripts the whole timeline, so every recording is the same apart from pids and times. It runs one headless Chromium page that frames a [ttyd](https://github.com/tsl0922/ttyd) terminal and `hallpass web` (whose `frame-ancestors`/`X-Frame-Options` headers it drops in that browser only), types the commands, clicks the answers with a drawn pointer and records the page with Puppeteer's screencast. The session gets its own `HOME`, `XDG_RUNTIME_DIR` and `XDG_CONFIG_HOME` in `WORKDIR`, so `hallpass web` only sees this session and the demo commands never write in your home.

Requirements: Go, `node` and `npm`, `ttyd`, `ffmpeg` (with libx264), and Chromium (on Ubuntu, `snap install chromium`). The Makefile runs `npm ci` in `demos/` to install `puppeteer-core`.

```console
$ make -C demos web   # about 1 minute
```

## Variables

Set with `make VAR=value`:

- `VHS`, `NODE`, `NPM`, `FFMPEG`: the tools, looked up in `$PATH` (`go install` puts `vhs` in `~/go/bin`).
- `CHROMIUM`: the browser for browser demos, default `/snap/bin/chromium`.
- `CRF`: the x264 quality of the encoded videos, default 30 (lower is better and bigger).
- `CHROMIUM_PROFILE`: prefix of the scratch profile, `-NAME` appended, created and removed by the recording. The snap can only write under `~/snap/chromium/common/`, hence the default `~/snap/chromium/common/hallpass-demo`; any directory works with a non-snap Chromium.
- `DEMO_TMPDIR`: where each recording's fresh directory is created with `mktemp`, default `$TMPDIR` or `/tmp`. It is removed after a successful run and kept on failure; a browser demo also leaves a screenshot of the page there (`raw.webm.error.png`). Its path shows in the web video: keep it short.
- `STRICT_HOST`: the ssh host the strict demo runs on, default `fedora` (an environment variable: the tape reads it).
