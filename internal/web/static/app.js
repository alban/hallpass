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
  if (out.length === 10) return "all";
  if ((ops & 0xff) === 0xff) return ["files", ...out.slice(8)].join(",");
  if ((ops & 0x300) === 0x300) return [...out.slice(0, -2), "network"].join(",");
  return out.join(",");
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

async function refreshRules(pid) {
  const s = sessions.get(pid);
  if (!s) return;
  const r = await fetch(`/api/sessions/${encodeURIComponent(pid)}/snapshot`);
  if (!r.ok) return;
  const snap = await r.json();
  s.rules = snap.rules || [];
  markDirty();
}

function openSession(info) {
  const pid = sessionKey(info);
  const s = { info, pending: new Map(), rules: [], ended: false };
  sessions.set(pid, s);
  s.src = new EventSource(`/api/sessions/${encodeURIComponent(pid)}/events`);
  s.src.onmessage = ev => {
    const batch = JSON.parse(ev.data);
    if (batch.snapshot) {
      // First batch of a (re)connection: start over.
      s.pending.clear();
      for (const r of batch.snapshot.pending || []) s.pending.set(r.id, r);
      s.rules = batch.snapshot.rules || [];
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
  };
  s.src.addEventListener("end", () => endSession(pid));
  s.src.onerror = () => {
    // EventSource retries by itself, unless the server refused.
    if (s.src.readyState === EventSource.CLOSED) endSession(pid);
  };
}

function endSession(pid) {
  const s = sessions.get(pid);
  if (!s || s.ended) return;
  s.ended = true;
  s.src.close();
  if (s.pending.size) pendingChanged = true;
  s.pending.clear();
  markDirty();
}

async function refreshSessions() {
  let r;
  try {
    r = await fetch("/api/sessions");
  } catch (e) {
    return;
  }
  if (r.status === 401) {
    document.getElementById("unpaired").hidden = false;
    document.querySelector("main").hidden = true;
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
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.text()).trim() || r.statusText);
}

function renderSessions() {
  const box = document.getElementById("sessions");
  box.replaceChildren();
  if (sessions.size === 0) {
    box.append(el("span", { class: "empty" }, "No hallpass session."));
    return;
  }
  for (const [pid, s] of sessions) {
    box.append(el("span", { class: "session" + (s.ended ? " ended" : ""), title: s.info.workdir || "" },
      sessionLabel(pid), " · ", s.info.mode || "", s.ended ? " · ended" : ""));
  }
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
  const buttons = el("div", { class: "buttons" },
    el("button", { class: "allow", onclick: answer("once") }, "Allow once"));
  if (p.scope) {
    buttons.append(
      el("button", { class: "allow", onclick: answer("temp") }, "Allow " + p.scope + " for " + TEMP_GRANT),
      el("button", { class: "allow", onclick: answer("always") }, "Always"));
  }
  buttons.append(
    el("button", { class: "deny", onclick: answer("deny") }, "Deny"),
    el("button", { class: "deny", onclick: answer("never") }, "Never" + (p.never ? " (" + p.never + ")" : "")));

  const origin = [(p.cmdline || []).join(" "), ...(p.parents || [])].filter(x => x).join(" ← ");
  const facts = (r.facts || []).map(f => f.kind + "=" + f.value + (f.trust && f.trust !== "TRUST_KERNEL" ? " (" + f.trust.replace("TRUST_", "").toLowerCase() + ")" : ""));
  return el("div", { class: "card" },
    el("div", {}, baseName(p.exe) + " (pid " + (p.pid || 0) + ") wants to " + (p.op || opName(r.op)) + ":"),
    el("div", { class: "path" }, p.path || (r.objects || []).map(objectText).join(" → ")),
    p.warn ? el("div", { class: "warn" }, p.warn) : null,
    p.note ? el("div", { class: "meta" }, "(" + p.note + ")") : null,
    origin ? el("div", { class: "meta" }, "by: " + origin) : null,
    facts.length ? el("div", { class: "meta" }, "facts: " + facts.join(", ")) : null,
    el("div", { class: "meta" }, "session " + sessionLabel(pid) + " · " + (r.syscall || "")),
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

function ruleRow(pid, r) {
  const o = r.object || {};
  let obj = "";
  if (o.path) obj = o.path.path + (o.path.tree ? "/**" : "");
  else if (o.proc) obj = "/proc: " + (o.proc.name || "*") + (o.proc.comm ? " of " + o.proc.comm : "");
  else if (o.unknown) obj = "(unknown paths)";
  else if (o.anyNet || o.ownListener || o.inet || o.unix) obj = "network: " + netMatchText(o);
  const verdict = (r.verdict || "ALLOW").toLowerCase();
  const err = el("span", { class: "error" });
  const remove = el("button", {
    onclick: async () => {
      try { await post(`/api/sessions/${encodeURIComponent(pid)}/rules`, { remove: [r.id] }); }
      catch (e) { err.textContent = e.message; }
    },
  }, "Remove");
  return el("tr", {},
    el("td", { class: "nowrap" }, String(r.id)),
    el("td", { class: "nowrap " + (verdict === "allow" ? "allow" : "deny") }, verdict),
    el("td", { class: "nowrap" }, opsNames(r.ops || 0)),
    el("td", {}, obj),
    el("td", {}, r.label || ""),
    el("td", {}, r.expires ? new Date(r.expires).toLocaleTimeString() : ""),
    el("td", {}, remove, err));
}

function renderRules() {
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
      if (set) {
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
  }
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

refreshSessions();
setInterval(refreshSessions, 2000);
