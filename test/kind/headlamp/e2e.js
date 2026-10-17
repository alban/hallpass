// Copyright The hallpass Authors
// SPDX-License-Identifier: Apache-2.0

// Drives Headlamp with the hallpass plugin through the kind e2e's
// requests (see answer.sh): checks the app-bar badge, the pod list column
// and the pod details section, answers "once" to /etc/once from the pod
// details and "deny" to /etc/denied from the hallpass view. Then sandboxes
// the Deployment of SANDBOX_POD with the policy e2e and waits for the
// session of its new pod.
//
// Environment:
//   URL       Headlamp's URL
//   CLUSTER   the cluster's name in Headlamp (the kubeconfig context)
//   SHOTS     directory for screenshots
//   SANDBOX_POD  a pod of the Deployment hallpass-e2e/sandboxed
//   CHROMIUM  browser to drive (default /snap/bin/chromium)
//   PROFILE   browser profile directory, created and removed here
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const puppeteer = require("puppeteer-core");

const URL = need("URL");
const CLUSTER = need("CLUSTER");
const SHOTS = path.resolve(need("SHOTS"));
const SANDBOX_POD = need("SANDBOX_POD");
const CHROMIUM = process.env.CHROMIUM || "/snap/bin/chromium";
const PROFILE = path.resolve(
  process.env.PROFILE || path.join(os.homedir(), "snap/chromium/common/hallpass-headlamp-e2e"));

// The mediated pod waits for each request until it is answered (the
// policy's askTimeout is 3 minutes).
const TIMEOUT = 180_000;

function need(name) {
  if (!process.env[name]) throw new Error(name + " is not set");
  return process.env[name];
}

function log(...args) {
  console.log("---", ...args);
}

let shot = 0;
async function screenshot(page, name) {
  shot++;
  await page.screenshot({ path: path.join(SHOTS, `${String(shot).padStart(2, "0")}-${name}.png`) });
}

async function waitText(page, text, timeout = TIMEOUT) {
  await page.waitForFunction(t => document.body && document.body.innerText.includes(t),
    { timeout, polling: 500 }, text);
}

async function badge(page) {
  return page.$eval('[data-testid="hallpass-badge"] .MuiBadge-badge', el =>
    el.classList.contains("MuiBadge-invisible") ? "0" : el.textContent.trim());
}

async function click(page, label) {
  const sel = `button[aria-label="${label}"]:not([disabled])`;
  await page.waitForSelector(sel, { timeout: TIMEOUT });
  await page.click(sel);
}

async function main() {
  fs.rmSync(PROFILE, { recursive: true, force: true });
  const browser = await puppeteer.launch({
    executablePath: CHROMIUM,
    headless: true,
    userDataDir: PROFILE,
    args: ["--no-first-run", "--window-size=1600,1000"],
    defaultViewport: { width: 1600, height: 1000 },
  });
  const page = await browser.newPage();
  const errors = [];
  page.on("console", m => {
    if (m.text().startsWith("hallpass:")) console.log("console:", m.type(), m.text());
  });
  page.on("pageerror", e => errors.push(String(e)));
  try {
    const c = `${URL}/c/${CLUSTER}`;

    log("hallpass view: waiting for the request for /etc/once");
    await page.goto(`${c}/hallpass`);
    await waitText(page, "/etc/once");
    await waitText(page, "connected");
    await page.waitForFunction(() => {
      const b = document.querySelector('[data-testid="hallpass-badge"] .MuiBadge-badge');
      return b && b.textContent.trim() === "1";
    }, { timeout: 30_000 });
    log(`badge: ${await badge(page)}`);
    await screenshot(page, "view-once");

    log("pod list: the hallpass column");
    await page.goto(`${c}/pods`);
    await waitText(page, "1 pending", 60_000);
    await screenshot(page, "pods");

    log("pod details: answering once");
    await page.goto(`${c}/pods/hallpass-e2e/mediated`);
    await waitText(page, "Mediated containers", 60_000);
    await waitText(page, "/etc/once", 60_000);
    await page.$eval('button[aria-label="once /etc/once"]', b => b.scrollIntoView({ block: "center" }));
    await screenshot(page, "pod-once");
    await click(page, "once /etc/once");

    log("hallpass view: answering deny");
    await page.goto(`${c}/hallpass`);
    await waitText(page, "/etc/denied");
    await screenshot(page, "view-denied");
    await click(page, "deny /etc/denied");
    await waitText(page, "No pending requests.", 30_000);
    await screenshot(page, "view-done");

    log(`pod action: sandboxing the Deployment of ${SANDBOX_POD}`);
    await page.goto(`${c}/pods/hallpass-e2e/${SANDBOX_POD}`);
    await click(page, "Sandbox with hallpass");
    await waitText(page, "Deployment sandboxed", 30_000);
    await page.click('[role="combobox"][aria-labelledby~="hallpass-policy"]');
    await page.waitForSelector('li[data-value="e2e"]', { timeout: 10_000 });
    await page.click('li[data-value="e2e"]');
    await screenshot(page, "sandbox");
    await page.evaluate(() => {
      const b = [...document.querySelectorAll("button")].find(b => b.textContent.trim() === "Apply");
      if (!b || b.disabled) throw new Error("no enabled Apply button");
      b.click();
    });
    await waitText(page, "now uses the hallpass policy e2e", 30_000);

    log("hallpass view: waiting for the session of the sandboxed pod");
    await page.goto(`${c}/hallpass`);
    await waitText(page, "hallpass-e2e/sandboxed-", 120_000);
    await screenshot(page, "view-sandboxed");
    if (errors.length) log("page errors:", errors.join("\n"));
    log("ok");
  } catch (e) {
    await screenshot(page, "failure").catch(() => {});
    fs.writeFileSync(path.join(SHOTS, "failure.html"), await page.content().catch(() => ""));
    if (errors.length) console.error("page errors:", errors.join("\n"));
    throw e;
  } finally {
    await browser.close();
    fs.rmSync(PROFILE, { recursive: true, force: true });
  }
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
