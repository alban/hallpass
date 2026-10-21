// Records demos/media/web.mp4: a shell under hallpass on the left (ttyd), `hallpass
// web` on the right, both in one headless Chromium page so they stay in sync.
// See demos/README.md. Run through `make -C demos web`.
//
// Environment:
//   HALLPASS   hallpass binary (required)
//   CHROMIUM   browser to drive (default /snap/bin/chromium)
//   PROFILE    browser profile directory, created and removed here; the snap
//              only writes under ~/snap/chromium/common/
//   WORKDIR    empty directory for the session's HOME, project and sockets
//   OUT        raw recording to write (.webm)
"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");
const puppeteer = require("puppeteer-core");

const HALLPASS = path.resolve(need("HALLPASS"));
const CHROMIUM = process.env.CHROMIUM || "/snap/bin/chromium";
const PROFILE = path.resolve(need("PROFILE"));
const WORKDIR = path.resolve(need("WORKDIR"));
const OUT = path.resolve(need("OUT"));

const W = 1920, H = 1080, BAR = 44, LEFT = 860, GAP = 8;
// The web UI's 14px text, enlarged to match the terminal's.
const ZOOM = 1.25;

function need(name) {
  if (!process.env[name]) throw new Error(name + " is not set");
  return process.env[name];
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    }).on("error", reject);
  });
}

// Catppuccin Mocha, like the VHS demo.
const THEME = {
  background: "#1e1e2e", foreground: "#cdd6f4", cursor: "#f5e0dc", selectionBackground: "#585b70",
  black: "#45475a", red: "#f38ba8", green: "#a6e3a1", yellow: "#f9e2af",
  blue: "#89b4fa", magenta: "#f5c2e7", cyan: "#94e2d5", white: "#bac2de",
  brightBlack: "#585b70", brightRed: "#f38ba8", brightGreen: "#a6e3a1", brightYellow: "#f9e2af",
  brightBlue: "#89b4fa", brightMagenta: "#f5c2e7", brightCyan: "#94e2d5", brightWhite: "#a6adc8",
};

// The page that holds both panes, the title cards and a mouse pointer (the
// screencast does not show the real one).
function layout(ttydURL, webURL) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
body { margin: 0; width: ${W}px; height: ${H}px; background: #11111b; overflow: hidden; font-family: sans-serif; }
.bar { position: absolute; top: 0; height: ${BAR}px; line-height: ${BAR}px; color: #cdd6f4; font-size: 20px; padding-left: 16px; box-sizing: border-box; }
.bar b { color: #f9e2af; font-weight: normal; font-family: monospace; }
iframe { position: absolute; top: ${BAR}px; height: ${H - BAR}px; border: 0; }
#term { left: 0; width: ${LEFT}px; }
#web { left: ${LEFT + GAP}px; width: ${(W - LEFT - GAP) / ZOOM}px; height: ${(H - BAR) / ZOOM}px; transform: scale(${ZOOM}); transform-origin: 0 0; background: #fff; }
#card { position: absolute; inset: 0; z-index: 20; background: #1e1e2e; color: #cdd6f4; display: flex; flex-direction: column; justify-content: center; padding-left: 160px; font-size: 30px; line-height: 1.6; transition: opacity .6s; }
#card h1 { font-size: 46px; margin: 0 0 .6em; }
#card.hidden { opacity: 0; pointer-events: none; }
#pointer { position: absolute; left: ${W - 300}px; top: ${H - 200}px; width: 28px; height: 28px; transition: left .9s ease-in-out, top .9s ease-in-out; pointer-events: none; z-index: 10; }
#pointer::after { content: ""; position: absolute; left: -14px; top: -14px; width: 28px; height: 28px; border-radius: 50%; background: #f9e2af; opacity: 0; }
#pointer.click::after { animation: click .5s; }
@keyframes click { from { opacity: .8; transform: scale(.3); } to { opacity: 0; transform: scale(1.6); } }
</style></head><body>
<div class="bar" style="left:0;width:${LEFT}px">Terminal: <b>hallpass --mediate=write -- sh</b></div>
<div class="bar" style="left:${LEFT + GAP}px">Browser: <b>hallpass web</b></div>
<iframe id="term" src="${ttydURL}"></iframe>
<iframe id="web" src="${webURL}"></iframe>
<svg id="pointer" viewBox="0 0 24 24"><path d="M3 2 L3 20 L8 15 L11.5 22 L14.5 20.5 L11 14 L18 14 Z" fill="#fff" stroke="#000" stroke-width="1.5"/></svg>
<div id="card"></div>
</body></html>`;
}

const procs = [];
function start(cmd, args, opts) {
  const p = spawn(cmd, args, opts);
  procs.push(p);
  return p;
}

async function main() {
  const home = path.join(WORKDIR, "home");
  const proj = path.join(WORKDIR, "example");
  const run = path.join(WORKDIR, "run");
  for (const d of [path.join(home, ".local", "bin"), run]) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, ".bashrc"), "# ~/.bashrc\n");
  fs.cpSync(path.join(__dirname, "..", "example"), proj, { recursive: true });

  // Only this demo's sessions, and nothing from the user's settings.
  const env = {
    ...process.env,
    HOME: home,
    XDG_RUNTIME_DIR: run,
    XDG_CONFIG_HOME: path.join(home, ".config"),
    DBUS_SESSION_BUS_ADDRESS: "",
    PATH: path.dirname(HALLPASS) + ":" + process.env.PATH,
    PS1: "$ ",
    TERM: "xterm-256color",
  };
  delete env.TMPDIR;
  // Not the recording's make: no "Entering directory" in the demo.
  for (const v of ["MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"]) delete env[v];

  const web = start(HALLPASS, ["web"], { env, stdio: ["pipe", "pipe", "pipe"] });
  let webOut = "";
  web.stdout.on("data", d => webOut += d);
  web.stderr.on("data", d => webOut += d);
  const waitWeb = async (re, what) => {
    for (const end = Date.now() + 10000; Date.now() < end; await sleep(100)) {
      const m = webOut.match(re);
      if (m) return m[1];
      if (web.exitCode !== null) break;
    }
    throw new Error(`hallpass web: no ${what}: ${webOut}`);
  };
  const webBase = await waitWeb(/open (http:\/\/127\.0\.0\.1:\d+)\//, "address");

  const ttydPort = await freePort();
  const ttydArgs = ["-i", "127.0.0.1", "-p", String(ttydPort), "-W",
    "-t", "fontSize=17", "-t", "theme=" + JSON.stringify(THEME),
    "-t", "disableLeaveAlert=true", "-t", "disableResizeOverlay=true",
    "-t", "titleFixed=hallpass demo", "bash", "--noprofile", "--norc"];
  const ttyd = start("ttyd", ttydArgs, { env, cwd: proj, stdio: ["ignore", "ignore", "pipe"] });
  let ttydErr = "";
  ttyd.stderr.on("data", d => ttydErr += d);
  for (let i = 0; ; i++) {
    const ok = await new Promise(r => net.connect(ttydPort, "127.0.0.1").on("connect", function () { this.end(); r(true); }).on("error", () => r(false)));
    if (ok) break;
    if (i > 50) throw new Error("ttyd did not start: " + ttydErr);
    await sleep(100);
  }

  const page0 = layout(`http://127.0.0.1:${ttydPort}/`, webBase + "/");
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.end(page0);
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  const layoutURL = `http://127.0.0.1:${server.address().port}/`;

  fs.rmSync(PROFILE, { recursive: true, force: true });
  const browser = await puppeteer.launch({
    executablePath: CHROMIUM,
    headless: true,
    userDataDir: PROFILE,
    defaultViewport: { width: W, height: H },
    args: ["--no-first-run", `--window-size=${W},${H}`, "--hide-scrollbars", "--font-render-hinting=none"],
  });
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on("pageerror", e => errors.push(String(e)));

    // Let the page frame hallpass web: it refuses to be framed
    // (frame-ancestors 'none', X-Frame-Options), so drop those headers on
    // its document. Only this recording browser sees the change.
    const cdp = await page.createCDPSession();
    await cdp.send("Fetch.enable", { patterns: [{ urlPattern: webBase + "/", requestStage: "Response" }] });
    cdp.on("Fetch.requestPaused", async ev => {
      try {
        const body = await cdp.send("Fetch.getResponseBody", { requestId: ev.requestId });
        const headers = (ev.responseHeaders || []).filter(h => !/^(x-frame-options|content-security-policy)$/i.test(h.name));
        headers.push({ name: "Content-Security-Policy", value: "default-src 'self'" });
        await cdp.send("Fetch.fulfillRequest", { requestId: ev.requestId, responseCode: ev.responseStatusCode, responseHeaders: headers, body: body.body });
      } catch (e) {
        errors.push("fetch: " + e);
      }
    });
    await page.goto(layoutURL);

    const frameOf = async id => (await (await page.$("#" + id)).contentFrame());
    const term = await frameOf("term");
    const webf = await frameOf("web");
    await term.waitForFunction(() => window.term && window.term.buffer, { timeout: 10000 });
    // Pair the web pane: confirm in hallpass web the code it shows.
    await webf.waitForFunction(() => /\d{3} \d{3}/.test(document.getElementById("pair-code").textContent), { timeout: 10000 });
    const shown = (await webf.$eval("#pair-code", e => e.textContent)).match(/\d{3} \d{3}/)[0];
    const asked = await waitWeb(/Pair the browser showing (\d{3} \d{3})\?/, "pairing question");
    if (asked !== shown) throw new Error(`pairing: hallpass web asks about ${asked}, the page shows ${shown}`);
    await sleep(700); // hallpass web ignores what is typed right after it asks
    web.stdin.write("y\n");
    await webf.waitForSelector("#sessions:not([hidden])", { timeout: 10000 });

    const screen = () => term.evaluate(() => {
      const b = window.term.buffer.active, out = [];
      for (let i = 0; i < b.length; i++) out.push(b.getLine(i).translateToString(true));
      return out.join("\n");
    });
    const waitScreen = async (re, timeout = 15000) => {
      for (const end = Date.now() + timeout; Date.now() < end; await sleep(100)) {
        if (re.test(await screen())) return;
      }
      throw new Error(`terminal: no ${re} in:\n${await screen()}`);
    };
    const waitNoScreen = async (re, timeout = 15000) => {
      for (const end = Date.now() + timeout; Date.now() < end; await sleep(100)) {
        if (!re.test(await screen())) return;
      }
      throw new Error(`terminal: still ${re}`);
    };
    const type = async (text, delay = 45) => {
      for (const c of text) {
        await term.evaluate(c => window.term.input(c), c);
        await sleep(delay);
      }
    };
    const enter = () => term.evaluate(() => window.term.input("\r"));
    const line = async (text, pause = 300) => { await type(text); await sleep(pause); await enter(); };
    const comment = async text => { await line("# " + text, 200); await sleep(700); };

    const card = async html => page.evaluate(h => {
      const c = document.getElementById("card");
      c.innerHTML = h;
      c.classList.toggle("hidden", !h);
    }, html);

    // Moves the pointer over the element of the web pane matched by find, then
    // clicks it.
    const click = async (find, arg) => {
      const box = await webf.evaluate((find, arg) => {
        const e = new Function("arg", find)(arg);
        if (!e) return null;
        e.scrollIntoView({ block: "nearest" });
        const r = e.getBoundingClientRect();
        return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
      }, find, arg);
      if (!box) throw new Error("web: nothing to click for " + arg);
      const x = LEFT + GAP + box.x * ZOOM, y = BAR + box.y * ZOOM;
      await page.evaluate((x, y) => {
        const p = document.getElementById("pointer");
        p.style.left = x + "px";
        p.style.top = y + "px";
      }, x, y);
      await sleep(1300);
      await page.evaluate(() => {
        const p = document.getElementById("pointer");
        p.classList.remove("click");
        void p.offsetWidth;
        p.classList.add("click");
      });
      await page.mouse.click(x, y);
    };
    const button = label => click(`
      const [path, label] = arg;
      const c = [...document.querySelectorAll(".card")].find(c => c.querySelector(".path").textContent.endsWith(path));
      return c && [...c.querySelectorAll("button")].find(b => b.textContent.startsWith(label));`, label);
    const nav = view => click(`return document.querySelector('nav button[data-view="' + arg + '"]')`, view);
    const waitCard = p => webf.waitForFunction(p => [...document.querySelectorAll(".card .path")].some(e => e.textContent.endsWith(p)), { timeout: 15000 }, p);

    // Hidden setup: a clean screen with the project as working directory.
    await term.evaluate(() => window.term.focus());
    await sleep(500);
    await term.evaluate(() => window.term.input("clear\r"));
    await sleep(500);

    await card(`<h1>hallpass web</h1><div>Follow and answer every hallpass session in a browser.</div><div>The terminal still asks too: the first answer wins.</div>`);
    await sleep(300);
    const rec = await page.screencast({ path: OUT, fps: 25 });
    await sleep(4000);
    await card("");
    await sleep(1000);

    // Files only: make, cc and the program built run without exec prompts.
    await line("hallpass --mediate=write -- sh");
    await sleep(1200);
    await webf.waitForFunction(() => document.querySelectorAll("#sessions .session").length > 0, { timeout: 10000 });
    await comment("inside the project: no question");
    await line("make && ./hello");
    await waitScreen(/^hello from/m);
    await sleep(1500);

    await comment("outside: asked here and in the browser");
    await line(`echo 'alias ll="ls -l"' >> ~/.bashrc`);
    await waitScreen(/wants to write/);
    await waitCard("/.bashrc");
    await sleep(2500);
    await button(["/.bashrc", "Deny"]);
    await waitNoScreen(/wants to write/);
    await sleep(2500);

    await comment("'Always' allows all of ~/.local for the session");
    await line("make install && ~/.local/bin/hello");
    await waitScreen(/hallpass: .* wants to/);
    await waitCard("/.local/bin");
    await sleep(2500);
    await button(["/.local/bin", "Always"]);
    await waitNoScreen(/hallpass: .* wants to/);
    await waitScreen(/^hello from[^]*^hello from/m);
    await sleep(2500);

    await nav("activity");
    await sleep(3500);
    await click(`return document.getElementById("filter")`, "filter");
    await sleep(300);
    await page.keyboard.type("answered", { delay: 90 });
    await sleep(3500);
    await nav("rules");
    await sleep(4500);

    await line("exit");
    await sleep(800);
    await nav("pending");
    await sleep(2500);

    await card(`<h1>hallpass</h1><div>Run your agent, answer for what it writes outside the project:</div><div>in the terminal, or in the browser.</div><div style="margin-top:1em;color:#f9e2af">github.com/alban/hallpass</div>`);
    await sleep(5000);
    await rec.stop();

    if (errors.length) throw new Error("page errors: " + errors.join("; "));
  } catch (e) {
    await browser.pages().then(ps => ps[ps.length - 1].screenshot({ path: OUT + ".error.png" })).catch(() => {});
    throw e;
  } finally {
    await browser.close();
    server.close();
    for (const p of procs) if (p.exitCode === null) p.kill();
    fs.rmSync(PROFILE, { recursive: true, force: true });
  }
}

main().catch(e => {
  console.error(e);
  for (const p of procs) if (p.exitCode === null) p.kill();
  process.exit(1);
});
