// Records demos/media/headlamp.mp4: a shell in a pod on the left (ttyd and
// kubectl exec), Headlamp with the hallpass plugin on the right, both in one
// headless Chromium page so they stay in sync. See demos/README.md. Run
// through `make -C demos headlamp`.
//
// Needs a kind cluster running hallpass-node, as `KEEP_CLUSTER=1 make
// test-kind` leaves it, docker for Headlamp, ttyd and kubectl.
//
// Environment:
//   PLUGIN       the plugin's directory, built (default ../../headlamp)
//   KUBECONTEXT  the cluster's context (default kind-hallpass-e2e)
//   HEADLAMP_IMAGE  default Headlamp v0.46.0, pinned by digest
//   BUSYBOX      the agent's image (default busybox:1.37)
//   CHROMIUM     browser to drive (default /snap/bin/chromium)
//   PROFILE      browser profile directory, created and removed here; the
//                snap only writes under ~/snap/chromium/common/
//   WORKDIR      empty directory for the kubeconfig and the plugin
//   OUT          raw recording to write (.webm)
"use strict";

const { execFileSync, spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const net = require("net");
const path = require("path");
const puppeteer = require("puppeteer-core");

const PLUGIN = path.resolve(process.env.PLUGIN || path.join(__dirname, "..", "..", "headlamp"));
const CONTEXT = process.env.KUBECONTEXT || "kind-hallpass-e2e";
const IMAGE = process.env.HEADLAMP_IMAGE ||
  "ghcr.io/headlamp-k8s/headlamp:v0.46.0@sha256:8a0ef97527544baa2b35825940ddf4db6e2d09c30cd5aa31fd269ff604cc8b75";
const BUSYBOX = process.env.BUSYBOX || "busybox:1.37";
const CHROMIUM = process.env.CHROMIUM || "/snap/bin/chromium";
const PROFILE = path.resolve(need("PROFILE"));
const WORKDIR = path.resolve(need("WORKDIR"));
const OUT = path.resolve(need("OUT"));

const W = 1920, H = 1080, BAR = 44, LEFT = 720, GAP = 8;
// Headlamp's text, enlarged to match the terminal's.
const ZOOM = 1.1;

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

async function waitPort(port, what) {
  for (let i = 0; ; i++) {
    const ok = await new Promise(r => net.connect(port, "127.0.0.1").on("connect", function () { this.end(); r(true); }).on("error", () => r(false)));
    if (ok) return;
    if (i > 600) throw new Error(what + " did not start");
    await sleep(100);
  }
}

const kubeconfig = path.join(WORKDIR, "kubeconfig");
function kubectl(...args) {
  return execFileSync("kubectl", ["--kubeconfig", kubeconfig, ...args], { encoding: "utf8" });
}

// Catppuccin Mocha, like the other demos.
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
<div class="bar" style="left:0;width:${LEFT}px">Terminal: <b>kubectl exec</b></div>
<div class="bar" style="left:${LEFT + GAP}px">Browser: <b>Headlamp</b> with the hallpass plugin</div>
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

let headlamp = "";
function cleanup() {
  for (const p of procs) if (p.exitCode === null) p.kill();
  if (headlamp) {
    try { execFileSync("docker", ["rm", "-f", headlamp], { stdio: "ignore" }); } catch { /* gone */ }
  }
}

async function main() {
  // The cluster's kubeconfig and the plugin, readable by Headlamp's user.
  fs.writeFileSync(kubeconfig, execFileSync("kubectl",
    ["config", "view", "--raw", "--minify", "--context", CONTEXT], { encoding: "utf8" }), { mode: 0o644 });
  const plugins = path.join(WORKDIR, "plugins");
  fs.mkdirSync(path.join(plugins, "hallpass"), { recursive: true });
  for (const f of ["dist/main.js", "dist/main.wasm.gz", "package.json"]) {
    fs.copyFileSync(path.join(PLUGIN, f), path.join(plugins, "hallpass", path.basename(f)));
  }
  for (const d of [WORKDIR, plugins, path.join(plugins, "hallpass")]) fs.chmodSync(d, 0o755);
  for (const f of fs.readdirSync(path.join(plugins, "hallpass"))) fs.chmodSync(path.join(plugins, "hallpass", f), 0o644);

  // A fresh agent Deployment, not sandboxed.
  const manifest = path.join(WORKDIR, "demo.yaml");
  fs.writeFileSync(manifest, fs.readFileSync(path.join(__dirname, "demo.yaml"), "utf8").replace("BUSYBOX", BUSYBOX));
  kubectl("delete", "--ignore-not-found", "--wait=true", "-f", manifest);
  kubectl("apply", "-f", manifest);
  kubectl("-n", "demo", "rollout", "status", "deploy/agent", "--timeout=120s");
  const pod = kubectl("-n", "demo", "get", "pod", "-l", "app=agent", "-o", "jsonpath={.items[0].metadata.name}");

  const hlPort = await freePort();
  headlamp = `hallpass-demo-headlamp-${process.pid}`;
  execFileSync("docker", ["run", "-d", "--name", headlamp, "--network", "host",
    "-v", `${kubeconfig}:/kubeconfig:ro`, "-v", `${plugins}:/headlamp/plugins:ro`,
    IMAGE, "-kubeconfig", "/kubeconfig", "-listen-addr", "127.0.0.1", "-port", String(hlPort)]);
  await waitPort(hlPort, "Headlamp");
  const hl = `http://127.0.0.1:${hlPort}/c/${CONTEXT}`;

  const env = {
    ...process.env,
    KUBECONFIG: kubeconfig,
    HOME: WORKDIR,
    PS1: "$ ",
    TERM: "xterm-256color",
  };
  for (const v of ["MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES"]) delete env[v];
  const ttydPort = await freePort();
  start("ttyd", ["-i", "127.0.0.1", "-p", String(ttydPort), "-W",
    "-t", "fontSize=17", "-t", "theme=" + JSON.stringify(THEME),
    "-t", "disableLeaveAlert=true", "-t", "disableResizeOverlay=true",
    "-t", "titleFixed=hallpass demo", "bash", "--noprofile", "--norc"],
  { env, cwd: WORKDIR, stdio: ["ignore", "ignore", "ignore"] });
  await waitPort(ttydPort, "ttyd");

  const page0 = layout(`http://127.0.0.1:${ttydPort}/`, `${hl}/pods/demo/${pod}`);
  const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "text/html");
    res.end(page0);
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));

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
    await page.goto(`http://127.0.0.1:${server.address().port}/`);

    const frameOf = async id => (await (await page.$("#" + id)).contentFrame());
    const term = await frameOf("term");
    const web = await frameOf("web");
    await term.waitForFunction(() => window.term && window.term.buffer, { timeout: 10000 });

    const screen = () => term.evaluate(() => {
      const b = window.term.buffer.active, out = [];
      for (let i = 0; i < b.length; i++) out.push(b.getLine(i).translateToString(true));
      return out.join("\n");
    });
    const waitScreen = async (re, timeout = 30000) => {
      for (const end = Date.now() + timeout; Date.now() < end; await sleep(100)) {
        if (re.test(await screen())) return;
      }
      throw new Error(`terminal: no ${re} in:\n${await screen()}`);
    };
    // The number of shell prompts in the pod, to wait for a command's end.
    const prompts = async () => ((await screen()).match(/^(~|\/workspace) # /gm) || []).length;
    const waitPrompts = async n => {
      for (const end = Date.now() + 30000; Date.now() < end; await sleep(100)) {
        if (await prompts() >= n) return;
      }
      throw new Error(`terminal: fewer than ${n} prompts in:\n${await screen()}`);
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
    const podLine = async text => { const n = await prompts(); await line(text); await waitPrompts(n + 1); };

    const card = async html => page.evaluate(h => {
      const c = document.getElementById("card");
      c.innerHTML = h;
      c.classList.toggle("hidden", !h);
    }, html);

    const webText = (t, timeout = 30000) => web.waitForFunction(t => document.body && document.body.innerText.includes(t),
      { timeout, polling: 200 }, t);
    // Moves the pointer over the element of Headlamp matched by find, then
    // clicks it.
    const click = async (find, arg, timeout = 30000) => {
      await web.waitForFunction((find, arg) => !!new Function("arg", find)(arg), { timeout, polling: 200 }, find, arg);
      const box = await web.evaluate((find, arg) => {
        const e = new Function("arg", find)(arg);
        e.scrollIntoView({ block: "nearest" });
        const r = e.getBoundingClientRect();
        return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
      }, find, arg);
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
    const enabled = `return document.querySelector('button[aria-label="' + arg + '"]:not([disabled])')`;
    const byText = sel => `return [...document.querySelectorAll('${sel}')].find(e => e.textContent.trim() === arg)`;

    // Hidden setup: Headlamp loaded, a clean terminal.
    await web.waitForSelector('button[aria-label="Sandbox with hallpass"]', { timeout: 60000 });
    await term.evaluate(() => window.term.focus());
    await sleep(500);
    await term.evaluate(() => window.term.input("clear\r"));
    await sleep(1000);

    await card(`<h1>hallpass on Kubernetes</h1><div>Sandbox an agent's Deployment from Headlamp,</div><div>then answer its writes outside its workspace in the browser.</div>`);
    await sleep(300);
    const rec = await page.screencast({ path: OUT, fps: 25 });
    await sleep(4000);
    await card("");
    await sleep(1500);

    await comment("an agent runs in a Deployment, not sandboxed");
    await sleep(1000);
    await click(enabled, "Sandbox with hallpass");
    await webText("Deployment agent");
    await sleep(2000);
    await click(`return document.querySelector('[role="combobox"][aria-labelledby~="hallpass-policy"]')`, "policy");
    await sleep(800);
    await click(`return document.querySelector('li[data-value="' + arg + '"]')`, "demo");
    await sleep(1000);
    await click(byText("button"), "Apply");
    await webText("now uses the hallpass policy demo");
    await sleep(1500);

    await line("kubectl -n demo rollout status deploy/agent");
    await waitScreen(/successfully rolled out/, 120000);
    await sleep(800);
    await line("kubectl -n demo exec -it deploy/agent -- sh");
    await waitPrompts(1);
    await sleep(800);
    await podLine("echo notes > notes.txt   # in the workspace: no question");
    await sleep(1200);

    const n = await prompts();
    await line("echo 'export EDITOR=vi' >> /etc/profile");
    await web.waitForFunction(() => {
      const b = document.querySelector('[data-testid="hallpass-badge"] .MuiBadge-badge');
      return b && b.textContent.trim() === "1" && !b.classList.contains("MuiBadge-invisible");
    }, { timeout: 30000, polling: 200 });
    await sleep(2000);
    await click(`return document.querySelector('[data-testid="hallpass-badge"]')`, "badge");
    await webText("/etc/profile");
    await sleep(2500);
    await click(enabled, "deny /etc/profile");
    await waitPrompts(n + 1);
    await sleep(2500);

    const m = await prompts();
    await line("echo 'cache=/workspace' > /etc/agent.conf");
    await webText("/etc/agent.conf");
    await sleep(2000);
    await click(enabled, "once /etc/agent.conf");
    await waitPrompts(m + 1);
    await sleep(1500);
    await podLine("cat /etc/agent.conf");
    await sleep(1500);

    await click(`return [...document.querySelectorAll('a')].find(a => a.textContent.startsWith(arg))`, "demo/agent-");
    await webText("Mediated containers");
    await sleep(1000);
    await web.evaluate(() => {
      const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (w.nextNode() && !w.currentNode.textContent.includes("Mediated containers"));
      w.currentNode.parentElement.scrollIntoView({ behavior: "smooth", block: "center" });
    });
    await sleep(4000);

    await line("exit");
    await sleep(2500);

    await card(`<h1>hallpass</h1><div>Run your agents in pods, answer for what they write outside their workspace:</div><div>with kubectl, or in Headlamp.</div><div style="margin-top:1em;color:#f9e2af">github.com/alban/hallpass</div>`);
    await sleep(5000);
    await rec.stop();

    if (errors.length) throw new Error("page errors: " + errors.join("; "));
  } catch (e) {
    await browser.pages().then(ps => ps[ps.length - 1].screenshot({ path: OUT + ".error.png" })).catch(() => {});
    throw e;
  } finally {
    await browser.close();
    server.close();
    cleanup();
    try { kubectl("delete", "--ignore-not-found", "--wait=false", "-f", manifest); } catch { /* best effort */ }
    fs.rmSync(PROFILE, { recursive: true, force: true });
  }
}

main().catch(e => {
  console.error(e);
  cleanup();
  process.exit(1);
});
