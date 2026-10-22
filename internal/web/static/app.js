// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// The hallpass web UI. The agent chooses the paths and command lines shown
// here: render them with textContent only, never as HTML.
"use strict";

// Sessions are keyed by their pid, or by their id when hallpass web follows
// a Kubernetes node agent (--node): the "pid" variables below hold that key.
const sessions = new Map(); // key -> {info, src, pending: Map(id -> Request), rules, ended}
const activity = []; // {pid: key, d: Decided | null, text}, oldest first
const maxActivity = 5000;
let view = "pending";
let dirty = false;
let pendingChanged = true; // re-rendering resets the cards' buttons and errors

const TEMP_GRANT = "5m0s"; // ui.TempGrant

// el builds an element; string children become text nodes.
function el(tag, props, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) {
    if (c === null || c === undefined || c === "") continue;
    e.append(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return e;
}

// opName mirrors rules.Op.String.
function opName(op) {
  op = op || 0;
  const names = [[1, "write"], [2, "create"], [4, "create directory"], [8, "create symlink"],
    [16, "delete"], [32, "link"], [64, "rename"], [128, "truncate"], [256, "connect"], [512, "send"]];
  for (const [bit, name] of names) if (op & bit) return name;
  return "?";
}

function opsNames(ops) {
  const names = ["write", "create", "mkdir", "symlink", "delete", "link", "rename", "truncate", "connect", "send"];
  const out = [];
  names.forEach((n, i) => { if (ops & (1 << i)) out.push(n); });
  const exec = ops & 0x400 ? ["exec"] : [];
  if (out.length === 10) return ["all", ...exec].join(",");
  if ((ops & 0xff) === 0xff) return ["write", ...out.slice(8), ...exec].join(",");
  if ((ops & 0x300) === 0x300) return [...out.slice(0, -2), "connect", ...exec].join(",");
  return [...out, ...exec].join(",");
}

function protoName(p) {
  return p === 6 ? "tcp" : p === 17 ? "udp" : "ip/" + (p || 0);
}

function inetAddr(addr, port) {
  return (addr.includes(":") ? "[" + addr + "]" : addr) + ":" + (port || 0);
}

function objectText(o) {
  if (!o) return "";
  if (o.path) return o.path.path;
  if (o.proc) return "/proc: " + (o.proc.name || "");
  if (o.inet) return protoName(o.inet.proto) + " " + inetAddr(o.inet.addr || "", o.inet.port) + (o.inet.ownListener ? " (listener started inside the sandbox)" : "");
  if (o.unix) return "unix " + (o.unix.abstract ? "@" + (o.unix.name || "") : o.unix.path || "") + (o.unix.ownListener ? " (listener started inside the sandbox)" : "");
  if ("unknown" in o) return "(unknown path: " + o.unknown + ")";
  return "?";
}

// netMatchText mirrors rules.ObjectMatch.NetString.
function netMatchText(o) {
  if (o.anyNet) return "all";
  if (o.ownListener) return "listeners started inside the sandbox";
  if (o.unix) {
    const u = o.unix;
    if (u.abstract) return "unix:@" + (u.name || "") + (u.prefix ? "*" : "");
    return "unix:" + (u.prefix ? (u.path || "").replace(/\/$/, "") + "/**" : u.path || "");
  }
  if (o.inet) {
    const i = o.inet;
    let s = i.proto ? protoName(i.proto) + ":" : "";
    const [addr, bits] = (i.prefix || "").split("/");
    const v6 = (addr || "").includes(":");
    if (!addr) s += "*";
    else s += (v6 ? "[" + addr + "]" : addr) + (bits && bits !== (v6 ? "128" : "32") ? "/" + bits : "");
    if (i.portLo || i.portHi) s += ":" + (i.portLo || 0) + ((i.portHi || 0) !== (i.portLo || 0) ? "-" + (i.portHi || 0) : "");
    return s;
  }
  return "";
}

function baseName(p) { return (p || "").split("/").pop(); }

function processText(subject) {
  const t = subject && subject.chain && subject.chain[0];
  if (!t) return "";
  // Decided events carry only the thread id and exe (cheap to read).
  return (t.comm || baseName(t.exe)) + " (" + (t.pid || t.tid || 0) + ")";
}

function reasonText(why) {
  return (why || []).map(r => {
    if (r.died) return "process died";
    if (r.rule) return "rule " + r.rule;
    if (r.builtin) return r.builtin;
    if (r.client) return "answered by " + r.client;
    return "default";
  }).join(", ");
}

function sessionKey(info) {
  return info.id || String(info.pid);
}

// sessionName is the pid, or namespace/pod/container for a node agent's.
function sessionName(pid) {
  const s = sessions.get(pid);
  const l = (s && s.info.labels) || {};
  return l.pod ? l.namespace + "/" + l.pod + "/" + l.container : pid;
}

function sessionLabel(pid) {
  const s = sessions.get(pid);
  const cmd = s && s.info.command ? s.info.command.join(" ") : "";
  return sessionName(pid) + (cmd ? " " + cmd : "");
}

function markDirty() {
  if (dirty) return;
  dirty = true;
  requestAnimationFrame(() => { dirty = false; render(); });
}

function addActivity(entry) {
  activity.push(entry);
  if (activity.length > maxActivity) activity.splice(0, activity.length - maxActivity);
}

// The credential, given by hallpass once the user confirmed the pairing. It
// lives in this variable only, never in a cookie or in storage, which the
// browser may write to its profile, where the sandbox could read it. Other
// tabs of the same server get it from a paired one (see borrowCredential);
// without one, reloading the page means pairing again.
let credential = null;
// onlySession is the session's key when the page was opened from a session,
// whose server shows only it; null for hallpass web.
let onlySession = null;
// tabID names this page to the server, which tells a session whether a
// page shows its requests (connected and visible): it then does not show
// them in desktop notifications too.
const tabID = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, "0")).join("");

// api fetches path with the credential. A 401 means the credential is not
// valid any more (hallpass restarted): pair again.
async function api(path, opts = {}) {
  const r = await fetch(path, { ...opts, headers: { ...(opts.headers || {}), Authorization: "Bearer " + credential } });
  if (r.status === 401 && pairState === "paired") unpaired("Not paired any more (hallpass restarted?).");
  return r;
}

class HTTPError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// sse reads the server-sent events at path, calling onEvent(type, data) for
// each, until the stream ends. Unlike EventSource, fetch can send the
// credential. It throws an HTTPError if the server refuses.
async function sse(path, signal, onEvent) {
  const r = await api(path, { signal });
  if (!r.ok) throw new HTTPError(r.status, (await r.text()).trim() || r.statusText);
  const reader = r.body.pipeThrough(new TextDecoderStream()).getReader();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += value;
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let type = "message";
      const data = [];
      for (const line of block.split("\n")) {
        if (line.startsWith(":")) continue; // comment: heartbeat
        const c = line.indexOf(":");
        const field = c < 0 ? line : line.slice(0, c);
        const v = c < 0 ? "" : line.slice(c + 1).replace(/^ /, "");
        if (field === "event") type = v;
        else if (field === "data") data.push(v);
      }
      if (data.length) onEvent(type, data.join("\n"));
    }
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function refreshRules(pid) {
  const s = sessions.get(pid);
  if (!s) return;
  const r = await api(`/api/sessions/${encodeURIComponent(pid)}/snapshot`);
  if (!r.ok) return;
  const snap = await r.json();
  s.rules = snap.rules || [];
  s.generation = snap.generation || "0";
  markDirty();
}

function onBatch(pid, s, batch) {
  if (batch.snapshot) {
    // First batch of a (re)connection: start over.
    s.pending.clear();
    for (const r of batch.snapshot.pending || []) s.pending.set(r.id, r);
    s.rules = batch.snapshot.rules || [];
    s.generation = batch.snapshot.generation || "0";
    pendingChanged = true;
  }
  for (const e of batch.events || []) {
    if (e.opened) { s.pending.set(e.opened.id, e.opened); pendingChanged = true; }
    else if (e.closed) { pendingChanged = s.pending.delete(e.closed.id) || pendingChanged; }
    else if (e.rules) refreshRules(pid);
    else if (e.decided) addActivity({ pid, d: e.decided });
    else if (e.warning) addActivity({ pid, text: "warning: " + e.warning });
    else if (e.dropped) addActivity({ pid, text: e.dropped + " events dropped (too slow)" });
  }
  markDirty();
}

// openSession follows the session's events until it ends, reconnecting
// like EventSource would: after a network error or a stream cut short, but
// not after the server refused or said "end".
function openSession(info) {
  const pid = sessionKey(info);
  const s = { info, pending: new Map(), rules: [], ended: false, abort: new AbortController() };
  sessions.set(pid, s);
  (async () => {
    while (!s.ended) {
      try {
        await sse(`/api/sessions/${encodeURIComponent(pid)}/events?tab=${tabID}&visible=${watching() ? "1" : "0"}&seq=${watchSeq}`, s.abort.signal, (type, data) => {
          if (type === "end") endSession(pid);
          else if (!s.ended) onBatch(pid, s, JSON.parse(data));
        });
      } catch (e) {
        if (e instanceof HTTPError) { endSession(pid); return; }
      }
      if (!s.ended) await sleep(2000);
    }
  })();
}

function endSession(pid) {
  const s = sessions.get(pid);
  if (!s || s.ended) return;
  s.ended = true;
  s.abort.abort();
  if (s.pending.size) pendingChanged = true;
  s.pending.clear();
  markDirty();
}

// Pairing: the page shows a code, and hallpass asks the user to confirm it
// where the sandbox can neither see nor answer: the terminal running hallpass
// web, the session's terminal, or a desktop notification.
let pairState = "unpaired"; // "pairing", "paired"

function showPairing(text, code) {
  document.getElementById("pairing").hidden = false;
  document.getElementById("sessions").hidden = true;
  document.querySelector("main").hidden = true;
  document.getElementById("pair-text").textContent = text;
  document.getElementById("pair-code").textContent = code ? "Pairing code: " + code : "";
  document.getElementById("pair-again").hidden = pairState !== "unpaired";
}

function showPaired() {
  document.getElementById("pairing").hidden = true;
  document.getElementById("sessions").hidden = false;
  document.querySelector("main").hidden = false;
}

function unpaired(text) {
  pairState = "unpaired";
  credential = null;
  for (const pid of sessions.keys()) endSession(pid);
  sessions.clear();
  showPairing(text);
}

async function pair() {
  if (pairState !== "unpaired") return;
  pairState = "pairing";
  showPairing("Asking hallpass to pair…");
  try {
    let r = await fetch("/api/pair", { method: "POST" });
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    const { id, code } = await r.json();
    showPairing("hallpass asks you to confirm this code: in the terminal running hallpass web, " +
      "or in the session's terminal or desktop notification. Confirm only if it shows the same code.", code);
    r = await fetch("/api/pair/wait", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
    const paired = await r.json();
    credential = paired.credential;
    onlySession = paired.session || null;
  } catch (e) {
    pairState = "unpaired";
    showPairing(e.message);
    return;
  }
  pairState = "paired";
  showPaired();
  refreshSessions();
}

// start borrows the credential of another tab of this server if there is
// one, and pairs otherwise.
async function start() {
  setTitle();
  pairState = "pairing"; // no "Pair again" meanwhile
  showPairing("Looking for a paired tab…");
  const got = await borrowCredential();
  pairState = "unpaired";
  if (got) {
    credential = got.credential;
    const r = await fetch("/api/sessions", { headers: { Authorization: "Bearer " + credential } }).catch(() => null);
    if (r && r.ok) {
      onlySession = got.session || null;
      pairState = "paired";
      showPaired();
      // The session opened a pairing window for this page, which it does
      // not need any more.
      api("/api/pair/close", { method: "POST" }).catch(() => {});
      refreshSessions();
      return;
    }
    credential = null;
  }
  pair();
}

// Tabs of the same server (same origin: BroadcastChannel crosses no other)
// share its credential: a new tab asks the paired ones instead of pairing
// again. Pages of other origins, and so other servers, cannot listen.
const channel = "BroadcastChannel" in window ? new BroadcastChannel("hallpass-credential") : null;
if (channel) {
  channel.addEventListener("message", (ev) => {
    if (ev.data && ev.data.type === "want" && pairState === "paired") {
      channel.postMessage({ type: "credential", credential, session: onlySession });
    }
  });
}

// borrowCredential asks the other tabs for the credential. Paired tabs
// answer at once; the wait only bounds how long the page looks for them.
function borrowCredential() {
  return new Promise((resolve) => {
    if (!channel) return resolve(null);
    const done = (v) => {
      clearTimeout(timer);
      channel.removeEventListener("message", onMessage);
      resolve(v);
    };
    const onMessage = (ev) => {
      if (ev.data && ev.data.type === "credential" && typeof ev.data.credential === "string") done(ev.data);
    };
    const timer = setTimeout(() => done(null), 300);
    channel.addEventListener("message", onMessage);
    channel.postMessage({ type: "want" });
  });
}

// setTitle names the page after what its server serves: one session (the
// web UI a session opens) or all of them (hallpass web).
async function setTitle() {
  let title = "hallpass web: all sessions";
  try {
    const r = await fetch("/api/scope");
    if (r.ok) {
      const s = await r.json();
      if (s.session) title = "hallpass: session " + s.session;
      else if (s.node) title = "hallpass web: node sessions";
    }
  } catch (e) {
    // Keep the default.
  }
  document.title = title;
  document.getElementById("title").textContent = title;
}

async function refreshSessions() {
  if (pairState !== "paired") return;
  let r;
  try {
    r = await api("/api/sessions");
  } catch (e) {
    return;
  }
  if (!r.ok) return;
  const infos = await r.json();
  const live = new Set();
  for (const info of infos) {
    live.add(sessionKey(info));
    const s = sessions.get(sessionKey(info));
    if (!s || s.ended) openSession(info);
    else s.info = info;
  }
  for (const [pid, s] of sessions) if (!live.has(pid)) endSession(pid);
  markDirty();
}

async function post(url, body) {
  const r = await api(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new HTTPError(r.status, (await r.text()).trim() || r.statusText);
}

function renderSessions() {
  const box = document.getElementById("sessions");
  box.replaceChildren();
  if (onlySession !== null) {
    // Opened from a session: no list, it shows this one only.
    const s = sessions.get(onlySession);
    box.append(el("span", { class: "only" },
      "This page follows one session: ", sessionLabel(onlySession), s && s.info.mode ? " (" + s.info.mode + ")" : "",
      s && s.ended ? ", ended" : "", ". For all your sessions, run ",
      el("a", { href: "https://alban.github.io/hallpass/answers/web/", target: "_blank", rel: "noopener noreferrer" }, "hallpass web"),
      "."));
    return;
  }
  if (sessions.size === 0) {
    box.append(el("span", { class: "empty" }, "No hallpass session."));
    return;
  }
  for (const [pid, s] of sessions) {
    box.append(el("span", { class: "session" + (s.ended ? " ended" : ""), title: s.info.workdir || "" },
      sessionLabel(pid), " · ", s.info.mode || "", s.ended ? " · ended" : ""));
  }
}

// grantForText formats a protojson Duration ("600s") like the terminal:
// "for 10m", or "for the rest of the session" when unset.
function grantForText(d) {
  const s = d ? Math.round(parseFloat(d)) : 0;
  if (!s) return "for the rest of the session";
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
  return "for " + (h ? h + "h" : "") + (m ? m + "m" : "") + (sec ? sec + "s" : "");
}

// advanceCard shows a request the program made in advance. Its reason is
// the program's own text: shown quoted, as its claim.
function advanceCard(pid, p, answer, err) {
  const forText = grantForText(p.grantFor);
  const buttons = el("div", { class: "buttons" },
    el("button", { class: "allow", onclick: answer("grant") }, "Grant " + forText),
    el("button", { class: "deny", onclick: answer("deny") }, "Deny"));
  const origin = [(p.cmdline || []).join(" "), ...(p.parents || [])].filter(x => x).join(" ← ");
  return el("div", { class: "card" },
    el("div", {}, baseName(p.exe) + " (pid " + (p.pid || 0) + ") asks in advance to " + (p.op || "write") + ":"),
    el("div", { class: "path" }, p.path || ""),
    el("div", {}, forText),
    p.warn ? el("div", { class: "warn" }, p.warn) : null,
    p.reason ? el("div", { class: "reason" }, "reason given by the program (unverified): ", el("q", {}, p.reason)) : null,
    origin ? el("div", { class: "meta" }, "by: " + origin) : null,
    el("div", { class: "meta" }, "session " + sessionLabel(pid) + " · request in advance"),
    buttons, err);
}

function pendingCard(pid, r) {
  const p = r.prompt || {};
  const err = el("div", { class: "error" });
  const answer = a => async ev => {
    ev.target.closest(".buttons").querySelectorAll("button").forEach(b => b.disabled = true);
    try {
      await post(`/api/sessions/${encodeURIComponent(pid)}/answer`, { request: r.id, answer: a });
    } catch (e) {
      err.textContent = e.message;
      ev.target.closest(".buttons").querySelectorAll("button").forEach(b => b.disabled = false);
    }
  };
  if (p.advance) return advanceCard(pid, p, answer, err);
  const buttons = el("div", { class: "buttons" },
    el("button", { class: "allow", onclick: answer("once") }, "Allow once"));
  if (p.scope) {
    buttons.append(
      el("button", { class: "allow", onclick: answer("temp") }, "Allow " + p.scope + " for " + TEMP_GRANT),
      el("button", { class: "allow", onclick: answer("always") }, "Always"));
  }
  if (p.programGroup) {
    buttons.append(el("button", { class: "allow", onclick: answer("group") }, "Group " + p.programGroup));
  }
  buttons.append(
    el("button", { class: "deny", onclick: answer("deny") }, "Deny"),
    el("button", { class: "deny", onclick: answer("never") }, "Never" + (p.never ? " (" + p.never + ")" : "")));

  const origin = [(p.cmdline || []).join(" "), ...(p.parents || [])].filter(x => x).join(" ← ");
  const facts = (r.facts || []).map(f => f.kind + "=" + f.value + (f.trust && f.trust !== "TRUST_KERNEL" ? " (" + f.trust.replace("TRUST_", "").toLowerCase() + ")" : ""));
  const op = p.op || opName(r.op);
  return el("div", { class: "card" },
    el("div", {}, baseName(p.exe) + " (pid " + (p.pid || 0) + ") wants to " + op + (op.endsWith(" to") ? "" : ":")),
    el("div", { class: "path" }, p.path ? (p.hostNames ? p.hostNames + " (" + p.path + ")" : p.path) : (r.objects || []).map(objectText).join(" → ")),
    p.warn ? el("div", { class: "warn" }, p.warn) : null,
    p.note ? el("div", { class: "meta" }, "(" + p.note + ")") : null,
    origin ? el("div", { class: "meta" }, "by: " + origin) : null,
    facts.length ? el("div", { class: "meta" }, "facts: " + facts.join(", ")) : null,
    el("div", { class: "meta" }, "session " + sessionLabel(pid) + " · " + (r.syscall || "") + (p.detail ? " · " + p.detail : "")),
    buttons, err);
}

function renderPending() {
  const box = document.getElementById("view-pending");
  box.replaceChildren();
  let n = 0;
  for (const [pid, s] of sessions) {
    const reqs = [...s.pending.values()].sort((a, b) => Number(a.id) - Number(b.id));
    for (const r of reqs) { box.append(pendingCard(pid, r)); n++; }
  }
  if (n === 0) box.append(el("p", { class: "empty" }, "Nothing waiting for an answer."));
  document.getElementById("pending-count").textContent = n ? "(" + n + ")" : "";
}

function activityRow(a) {
  if (!a.d) {
    return el("tr", {}, el("td", {}, ""), el("td", {}, sessionName(a.pid)), el("td", { colspan: "5" }, a.text));
  }
  const d = a.d;
  const time = d.time ? new Date(d.time).toLocaleTimeString() : "";
  return el("tr", {},
    el("td", { class: "nowrap" }, time),
    el("td", { class: "nowrap" }, sessionName(a.pid)),
    el("td", { class: "nowrap " + (d.allowed ? "allow" : "deny") }, d.allowed ? "allow" : "deny"),
    el("td", { class: "nowrap" }, d.op ? opName(d.op) : (d.syscall || "")),
    el("td", {}, (d.objects || []).map(objectText).join(" → ")),
    el("td", {}, processText(d.subject)),
    el("td", {}, reasonText(d.why)));
}

function renderActivity() {
  const body = document.getElementById("activity");
  const words = document.getElementById("filter").value.toLowerCase().split(/\s+/).filter(w => w);
  const rows = [];
  for (let i = activity.length - 1; i >= 0 && rows.length < 500; i--) {
    const row = activityRow(activity[i]);
    const text = row.textContent.toLowerCase();
    if (words.every(w => text.includes(w))) rows.push(row);
  }
  body.replaceChildren(...rows);
}

// forText gives what is left of an expiry, rounded down, as a "for"
// suffix: an edit can keep an expiry, not extend it. Less than a second
// left is a second, not no expiry.
function forText(expires) {
  if (!expires) return "";
  const secs = Math.floor((new Date(expires) - Date.now()) / 1000);
  if (secs <= 0) return " for 1s";
  return " for " + (secs >= 120 ? Math.floor(secs / 60) + "m" : secs + "s");
}

const RULE_SYNTAX = `VERDICT KIND VALUE [for DURATION]
  VERDICT    allow, deny or ask
  write P    writing the file P (creating, deleting... it too); P/** the tree below P
  exec P     running the program P; P/** every program below P
  connect N  a destination: tcp:1.2.3.4:443, [2001:db8::1]:22, unix:/run/x.sock, unix:@name, all...
  proc N C   /proc/<pid>/N of the processes named C
  unknown    the paths that could not be read (lite mode)
  DURATION   e.g. 10m or 2h; without it, until removed
An allow rule gives at most what answering "always" would, or narrows the rule it replaces.`; // rules.SpecSyntax

// monitor.ProtectedSet: the server refuses to change these denials.
const PROTECTED_SET = "protected";

// The open rule editors, by "pid/id" ("pid/new" to add one): their text
// and error survive re-rendering.
const ruleEditors = new Map();
let focusEditor = ""; // the editor just opened
let rulesShown = ""; // what renderRules last showed, to re-render only on changes

function editorKey(pid, id) { return pid + "/" + id; }

// changeRules posts a rules change. When it applies to the rules as they
// were (ifGeneration) and they changed meanwhile, it refreshes them and
// says so.
async function changeRules(pid, body, ed) {
  const s = sessions.get(pid);
  try {
    await post(`/api/sessions/${encodeURIComponent(pid)}/rules`, body);
    return true;
  } catch (e) {
    if (e.status === 409) {
      ed.error = "The rules changed meanwhile: check them and save again.";
      if (s) {
        await refreshRules(pid);
        ed.generation = s.generation;
      }
    } else ed.error = e.message;
    markRulesDirty();
    return false;
  }
}

function markRulesDirty() { rulesShown = ""; markDirty(); }

function ruleEditor(pid, key, onSave, saveText) {
  const ed = ruleEditors.get(key);
  const input = el("input", { class: "spec", type: "text", "data-editor": key, placeholder: "allow write /home/me/src/** for 1h", spellcheck: "false" });
  input.value = ed.text;
  input.addEventListener("input", () => { ed.text = input.value; });
  const save = async () => {
    ed.error = "";
    if (await onSave(ed)) ruleEditors.delete(key);
    markRulesDirty();
  };
  input.addEventListener("keydown", e => {
    if (e.key === "Enter") save();
    if (e.key === "Escape") { ruleEditors.delete(key); markRulesDirty(); }
  });
  return el("span", { class: "editor" }, input,
    el("button", { onclick: save }, saveText),
    el("button", { onclick: () => { ruleEditors.delete(key); markRulesDirty(); } }, "Cancel"),
    el("span", { class: "error" }, ed.error || ""));
}

function ruleRow(pid, r) {
  const o = r.object || {};
  let obj = "";
  if (o.path) obj = o.path.path + (o.path.tree ? "/**" : "");
  else if (o.proc) obj = "/proc: " + (o.proc.name || "*") + (o.proc.comm ? " of " + o.proc.comm : "");
  else if (o.unknown) obj = "(unknown paths)";
  else if (o.anyNet || o.ownListener || o.inet || o.unix) obj = "network: " + netMatchText(o);
  const verdict = (r.verdict || "ALLOW").toLowerCase();
  const key = editorKey(pid, r.id);
  const s = sessions.get(pid);
  if (ruleEditors.has(key)) {
    // An edit replaces the rule, in one change that fails if the rules
    // changed since this page read them. Group labels go with the rules
    // the group gave.
    const label = (r.label || "").startsWith("@") ? "" : r.label || "";
    return el("tr", {},
      el("td", { class: "nowrap" }, String(r.id)),
      el("td", { colspan: "6" }, ruleEditor(pid, key,
        ed => changeRules(pid, { remove: [r.id], add: [ed.text], label, ifGeneration: ed.generation }, ed), "Save")));
  }
  const err = el("span", { class: "error" });
  const edit = el("button", {
    onclick: () => {
      ruleEditors.set(key, { text: (r.spec || "") + forText(r.expires), error: "", generation: s.generation });
      focusEditor = key;
      markRulesDirty();
    },
  }, "Edit");
  const remove = el("button", {
    onclick: async () => {
      try { await post(`/api/sessions/${encodeURIComponent(pid)}/rules`, { remove: [r.id] }); }
      catch (e) { err.textContent = e.message; }
    },
  }, "Delete");
  return el("tr", {},
    el("td", { class: "nowrap" }, String(r.id)),
    el("td", { class: "nowrap " + (verdict === "allow" ? "allow" : "deny") }, verdict),
    el("td", { class: "nowrap" }, opsNames(r.ops || 0)),
    el("td", {}, obj),
    el("td", {}, r.label || ""),
    el("td", {}, r.expires ? new Date(r.expires).toLocaleTimeString() : ""),
    el("td", {}, ...(r.set === PROTECTED_SET ? [] : r.spec ? [edit, " ", remove, err] : [remove, err])));
}

function addRuleForm(pid) {
  const key = editorKey(pid, "new");
  if (!ruleEditors.has(key)) {
    return el("p", {}, el("button", {
      onclick: () => { ruleEditors.set(key, { text: "", error: "" }); focusEditor = key; markRulesDirty(); },
    }, "Add rule"));
  }
  return el("div", { class: "add-rule" },
    ruleEditor(pid, key, ed => changeRules(pid, { add: [ed.text] }, ed), "Add"),
    el("pre", { class: "syntax" }, RULE_SYNTAX));
}

function renderRules() {
  const shown = JSON.stringify([...sessions].map(([pid, s]) => [pid, s.ended, s.generation, s.rules]));
  if (shown === rulesShown) return; // keeps the editors' focus
  rulesShown = shown;
  const focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.editor : undefined;
  const box = document.getElementById("view-rules");
  box.replaceChildren();
  for (const [pid, s] of sessions) {
    if (s.ended) continue;
    box.append(el("h2", {}, "Session " + sessionLabel(pid)));
    const sets = new Map();
    for (const r of s.rules) {
      const k = r.set || "";
      if (!sets.has(k)) sets.set(k, []);
      sets.get(k).push(r);
    }
    for (const [set, rules] of sets) {
      const head = el("div", {}, "Set: " + (set || "(none)") + " ");
      if (set && set !== PROTECTED_SET) {
        const err = el("span", { class: "error" });
        head.append(el("button", {
          onclick: async () => {
            if (!confirm(`Remove every rule of set "${set}" from session ${sessionName(pid)}? Its denies protect files too.`)) return;
            try { await post(`/api/sessions/${encodeURIComponent(pid)}/rules`, { removeSets: [set] }); }
            catch (e) { err.textContent = e.message; }
          },
        }, "Remove set"), err);
      }
      box.append(head, el("table", {},
        el("thead", {}, el("tr", {}, ...["Id", "Verdict", "Ops", "Object", "Label", "Expires", ""].map(h => el("th", {}, h)))),
        el("tbody", {}, ...rules.map(r => ruleRow(pid, r)))));
    }
    if (s.rules.length === 0) box.append(el("p", { class: "empty" }, "No rules."));
    box.append(addRuleForm(pid));
  }
  if (focused || focusEditor) {
    const input = box.querySelector(`input[data-editor="${CSS.escape(focused || focusEditor)}"]`);
    if (input) input.focus();
  }
  focusEditor = "";
}

function render() {
  renderSessions();
  if (pendingChanged) {
    pendingChanged = false;
    renderPending(); // also updates the count in the tab
  }
  if (view === "activity") renderActivity();
  if (view === "rules") renderRules();
}

for (const b of document.querySelectorAll("nav button")) {
  b.addEventListener("click", () => {
    view = b.dataset.view;
    for (const o of document.querySelectorAll("nav button")) o.classList.toggle("active", o === b);
    for (const v of ["pending", "activity", "rules"]) document.getElementById("view-" + v).hidden = v !== view;
    render();
  });
}
document.getElementById("filter").addEventListener("input", renderActivity);
document.getElementById("pair-again").addEventListener("click", pair);
// A covered window is still "visible": the page counts as watched only while
// its window also has the focus.
function watching() {
  return document.visibilityState === "visible" && document.hasFocus();
}
// Numbers the reports: the server keeps the latest, whatever the order the
// requests arrive in.
let watchSeq = 0;
function reportWatching() {
  if (pairState !== "paired") return;
  api("/api/visibility", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ tab: tabID, visible: watching(), seq: ++watchSeq }),
  }).catch(() => {});
}
document.addEventListener("visibilitychange", reportWatching);
window.addEventListener("focus", reportWatching);
window.addEventListener("blur", reportWatching);

start();
setInterval(refreshSessions, 2000);
