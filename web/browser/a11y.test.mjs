// Accessibility and layout in a real browser. jsdom has no layout, so the
// unit tests turn axe's contrast rule off; this run keeps every rule on and
// also checks reflow at 320 CSS pixels (WCAG 1.4.10) and the skip link.
//
// Needs the Python package importable (PYTHONPATH=../src, or installed) and
// Chromium from `npx playwright install chromium`.

import { spawn } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const ROOT = resolve(import.meta.dirname, "..", "..");

const VIEWPORTS = [
  { name: "desktop", width: 1280, height: 800 },
  { name: "phone", width: 375, height: 812 },
  { name: "reflow", width: 320, height: 640 },
];
const THEMES = ["light", "dark"];

/** @type {import("node:child_process").ChildProcess} */
let server;
/** @type {string} */
let base;
/** @type {import("playwright").Browser} */
let browser;
/** @type {string} */
let work;
/** @type {string} */
let scanId;

before(async () => {
  work = mkdtempSync(join(tmpdir(), "checkstead-a11y-"));
  cpSync(join(ROOT, "ui", "scans"), join(work, "scans"), { recursive: true });
  server = spawn(
    process.env.PYTHON || "python3",
    ["-m", "checkstead", "ui", "--scans", join(work, "scans"), "--data", join(work, "data"), "--host", "127.0.0.1", "--port", "0"],
    { env: { ...process.env, PYTHONPATH: join(ROOT, "src"), PYTHONUNBUFFERED: "1", CHECKSTEAD_LOCAL: "" }, stdio: ["ignore", "pipe", "inherit"] },
  );
  base = await new Promise((done, failed) => {
    let seen = "";
    server.stdout.on("data", (chunk) => {
      seen += chunk;
      const match = /checkstead ui\s+(http:\/\/[^\s/]+)\//.exec(seen);
      if (match) done(match[1]);
    });
    server.on("exit", (code) => failed(new Error(`server exited ${code}: ${seen}`)));
  });
  browser = await chromium.launch();
  const page = await browser.newPage();
  const signIn = await page.request.post(`${base}/api/session/local`, { headers: { Origin: base }, data: {} });
  assert.equal(signIn.status(), 200, "localhost sign-in");
  const history = await (await page.request.get(`${base}/api/history`)).json();
  scanId = history.scans[0].id;
  await page.close();
});

after(async () => {
  await browser?.close();
  server?.kill();
  if (work) rmSync(work, { recursive: true, force: true });
});

/**
 * @param {string} theme
 * @param {{width: number, height: number}} size
 * @param {boolean} signedIn
 */
async function open(theme, size, signedIn) {
  // bypassCSP only so axe can be injected; the app's own CSP is tested in Python.
  const context = await browser.newContext({ viewport: size, colorScheme: /** @type {"light"|"dark"} */ (theme), bypassCSP: true, reducedMotion: "reduce" });
  if (signedIn) {
    const signIn = await context.request.post(`${base}/api/session/local`, { headers: { Origin: base }, data: {} });
    assert.equal(signIn.status(), 200);
  }
  return context;
}

/** @param {import("playwright").Page} page */
async function settle(page) {
  await page.waitForLoadState("networkidle");
  await page.waitForSelector("h1");
  await page.evaluate(() => document.fonts.ready);
}

/** @param {import("playwright").Page} page */
async function axe(page) {
  await page.addScriptTag({ content: AXE });
  return page.evaluate(async () => {
    // @ts-ignore axe is injected above.
    const result = await window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"] } });
    return result.violations.map((/** @type {any} */ v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      nodes: v.nodes.slice(0, 5).map((/** @type {any} */ n) => `${n.target.join(" ")} :: ${n.failureSummary.split("\n").slice(1, 3).join(" ").trim()}`),
    }));
  });
}

/** @param {import("playwright").Page} page */
async function horizontalOverflow(page) {
  return page.evaluate(() => {
    const width = document.documentElement.clientWidth;
    const scroll = document.documentElement.scrollWidth;
    if (scroll <= width + 1) return null;
    // Name the widest element that is not inside its own scroll container,
    // so a failure says what to fix. Tables may scroll inside a wrapper.
    const culprits = [];
    for (const element of document.body.querySelectorAll("*")) {
      const box = element.getBoundingClientRect();
      if (box.right <= width + 1) continue;
      let parent = element.parentElement;
      let contained = false;
      while (parent && parent !== document.body) {
        const style = getComputedStyle(parent);
        if (/(auto|scroll|hidden)/.test(style.overflowX) && parent.getBoundingClientRect().right <= width + 1) {
          contained = true;
          break;
        }
        parent = parent.parentElement;
      }
      if (!contained) culprits.push(`${element.tagName.toLowerCase()}${element.className ? "." + String(element.className).split(" ").join(".") : ""} right=${Math.round(box.right)}`);
    }
    return { width, scroll, culprits: culprits.slice(0, 5) };
  });
}

function routes() {
  return [
    ["overview", "#/"],
    ["repositories", "#/repositories"],
    ["scans", "#/scans"],
    ["scan findings", `#/scans/${encodeURIComponent(scanId)}`],
    ["scan changes", `#/scans/${encodeURIComponent(scanId)}/changes`],
    ["scan dependencies", `#/scans/${encodeURIComponent(scanId)}/dependencies`],
    ["scan evidence", `#/scans/${encodeURIComponent(scanId)}/evidence`],
    ["evidence", "#/evidence"],
    ["CI runs", "#/builds"],
    ["access", "#/access"],
    ["not found", "#/no-such-page"],
  ];
}

for (const theme of THEMES) {
  for (const size of VIEWPORTS) {
    describe(`${theme} ${size.name} ${size.width}px`, () => {
      test("sign-in page", async () => {
        const context = await open(theme, size, false);
        const page = await context.newPage();
        await page.goto(`${base}/`);
        await settle(page);
        assert.deepEqual(await axe(page), []);
        assert.equal(await horizontalOverflow(page), null);
        await context.close();
      });

      test("every signed-in page", async () => {
        const context = await open(theme, size, true);
        const page = await context.newPage();
        const failures = [];
        for (const [name, hash] of routes()) {
          await page.goto(`${base}/${hash}`);
          await settle(page);
          const violations = await axe(page);
          if (violations.length) failures.push({ page: name, violations });
          const overflow = await horizontalOverflow(page);
          if (overflow) failures.push({ page: name, overflow });
        }
        assert.deepEqual(failures, []);
        await context.close();
      });
    });
  }
}

test("the skip link is the first stop and moves focus to the content", async () => {
  const context = await open("light", VIEWPORTS[0], true);
  const page = await context.newPage();
  await page.goto(`${base}/#/scans`);
  await settle(page);
  await page.keyboard.press("Tab");
  const first = await page.evaluate(() => ({ text: document.activeElement?.textContent?.trim(), href: document.activeElement?.getAttribute("href") }));
  assert.match(first.text || "", /skip/i);
  const visible = await page.evaluate(() => {
    const box = document.activeElement?.getBoundingClientRect();
    return Boolean(box && box.width > 0 && box.height > 0 && box.top >= 0);
  });
  assert.ok(visible, "the focused skip link is visible");
  await page.keyboard.press("Enter");
  const inMain = await page.evaluate(() => Boolean(document.activeElement?.closest("main")) || document.activeElement?.id === "main");
  assert.ok(inMain, "Enter on the skip link moves focus into main");
  await context.close();
});
