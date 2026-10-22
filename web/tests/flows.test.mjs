// Whole-app flows against a fake API, with an axe check on every view.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/checkstead/static/js/api.js";
import { createApp } from "../../src/checkstead/static/js/app.js";
import { NOW, axe, fakeApi, freshDom, history, rejecting, repositories, settle } from "./helpers.mjs";

async function boot(hash, overrides = {}) {
  const dom = freshDom(hash);
  const { api, calls } = fakeApi(overrides);
  const root = document.getElementById("app");
  const app = createApp({ root, api, now: () => NOW, storage: null });
  await app.start();
  await settle();
  return { dom, root, app, calls };
}

async function go(dom, hash) {
  dom.window.location.hash = hash;
  dom.window.dispatchEvent(new dom.window.HashChangeEvent("hashchange"));
  await settle();
}

const text = (root) => root.textContent.replace(/\s+/g, " ");

test("signed out: the gate shows only the enabled methods", async () => {
  const { dom, root, calls } = await boot("#/", { session: rejecting(new ApiError("auth", "Sign in first.", 401)) });
  assert.match(text(root), /Sign in with GitHub/);
  assert.match(text(root), /Sign in on this computer/);
  assert.doesNotMatch(text(root), /Microsoft/);
  assert.ok(!calls.some(([name]) => name === "history"), "no data is requested before sign-in");
  assert.deepEqual(await axe(dom), []);
});

test("signing in on this computer opens the overview", async () => {
  let signed = false;
  const { root, calls } = await boot("#/", {
    session: () => (signed ? Promise.resolve({ user: { id: 1, provider: "local", login: "local", displayName: "", role: "admin" } }) : Promise.reject(new ApiError("auth", "Sign in first.", 401))),
    signInLocal: () => { signed = true; return Promise.resolve({}); },
  });
  [...root.querySelectorAll("button")].find((b) => /this computer/.test(b.textContent)).click();
  await settle();
  assert.ok(calls.some(([name]) => name === "signInLocal"));
  assert.match(text(root), /Signed in on this computer/);
  assert.match(text(root), /Needs attention/);
});

test("overview: evidence chain, attention, and counts from real fields", async () => {
  const { dom, root } = await boot("#/");
  const body = text(root);
  assert.match(body, /Vulnerability data/);
  assert.match(body, /Key checkstead-2026-10/);
  assert.match(body, /1 finding actively exploited/);
  assert.match(body, /2 critical findings/);
  assert.match(body, /not endorsed or certified by the NVD/);
  assert.equal(root.querySelector('a[aria-current="page"]').textContent.trim(), "Overview");
  assert.deepEqual(await axe(dom), []);
});

test("overview: an empty server explains how to get the first scan", async () => {
  const { dom, root } = await boot("#/", { history: { notice: "", scans: [], drifts: [] } });
  assert.match(text(root), /No scans yet/i);
  assert.deepEqual(await axe(dom), []);
});

test("load failures show the cause and recover on retry", async () => {
  let fail = true;
  const { root } = await boot("#/", { history: () => (fail ? Promise.reject(new ApiError("offline", "The server could not be reached.")) : Promise.resolve(history())) });
  assert.match(text(root), /cannot be reached/);
  fail = false;
  [...root.querySelectorAll("button")].find((b) => b.textContent === "Try again").click();
  await settle();
  assert.match(text(root), /Needs attention/);
});

test("an expired session during a load returns to sign-in", async () => {
  const { root } = await boot("#/", { history: rejecting(new ApiError("auth", "Sign in first.", 401)) });
  assert.match(text(root), /Sign in/);
  assert.equal(root.querySelector(".rail"), null);
});

test("going offline says the data is not updating", async () => {
  const { dom, root } = await boot("#/");
  dom.window.dispatchEvent(new dom.window.Event("offline"));
  await settle();
  assert.match(text(root), /You are offline\./);
  dom.window.dispatchEvent(new dom.window.Event("online"));
  await settle();
  assert.doesNotMatch(text(root), /You are offline\./);
});

test("scan views: findings, changes, dependencies, evidence", async () => {
  const { dom, root, calls } = await boot("#/scans/02-new");
  assert.ok(!calls.some(([name]) => name === "scan"), "findings come from the summary; the full scan loads only when needed");
  assert.match(text(root), /CVE-2021-44228/);
  assert.match(text(root), /Direct, production/);
  assert.deepEqual(await axe(dom), [], "findings");
  await go(dom, "#/scans/02-new/changes");
  assert.ok(calls.some(([name, id]) => name === "scan" && id === "02-new"));
  assert.match(text(root), /log4j-core/);
  assert.deepEqual(await axe(dom), [], "changes");
  await go(dom, "#/scans/02-new/dependencies");
  assert.match(text(root), /lodash/);
  assert.deepEqual(await axe(dom), [], "dependencies");
  await go(dom, "#/scans/02-new/evidence");
  assert.match(text(root), /checkstead-2026-10/);
  assert.deepEqual(await axe(dom), [], "evidence");
});

test("an unknown scan says it is not there", async () => {
  const { root } = await boot("#/scans/missing", { scan: rejecting(new ApiError("not-found", "No scan with that id.", 404)) });
  assert.match(text(root), /No scan with that id\.|not found|could not be loaded/i);
});

test("evidence, CI runs and not-found pages pass axe", async () => {
  const { dom, root } = await boot("#/evidence");
  assert.deepEqual(await axe(dom), [], "evidence");
  await go(dom, "#/builds");
  assert.match(text(root), /GitHub/);
  assert.deepEqual(await axe(dom), [], "builds");
  await go(dom, "#/nowhere");
  assert.match(text(root), /not found|no page/i);
  assert.deepEqual(await axe(dom), [], "not-found");
});

test("access: an administrator adds a person", async () => {
  const { dom, root, calls } = await boot("#/access");
  assert.match(text(root), /bo@example\.com/);
  assert.deepEqual(await axe(dom), []);
  root.querySelector("#add-login").value = "  carol  ";
  root.querySelector("#add-role").value = "admin";
  root.querySelector("form").dispatchEvent(new dom.window.Event("submit", { cancelable: true, bubbles: true }));
  await settle();
  assert.deepEqual(calls.find(([name]) => name === "addUser")[1], { provider: "github", login: "carol", role: "admin" });
  assert.match(text(root), /Added carol\./);
});

test("access: removal needs a second press", async () => {
  const { root, calls } = await boot("#/access");
  const remove = root.querySelector('button[aria-label="Remove bo@example.com"]');
  remove.click();
  await settle();
  assert.ok(!calls.some(([name]) => name === "removeUser"));
  root.querySelector('button[aria-label="Confirm removing bo@example.com"]').click();
  await settle();
  assert.deepEqual(calls.find(([name]) => name === "removeUser").slice(1), [2]);
});

test("repositories: synced organization, grouped by project, with each branch's newest result", async () => {
  const { dom, root } = await boot("#/repositories", { repositories: repositories() });
  const page = text(root);
  assert.match(page, /Azure DevOps: acme/);
  assert.match(page, /Proarc-Products \(1\)/);
  assert.match(page, /Tools \(1\)/);
  assert.match(page, /Passes, 2 findings/);
  assert.match(page, /2 branches/);
  assert.match(page, /Fails policy/);
  assert.match(page, /not scanned/);
  // GitHub is not connected, so it gets no section.
  assert.doesNotMatch(page, /GitHub repositories/);
  const web = [...root.querySelectorAll("a")].find((a) => a.textContent === "web-app");
  assert.equal(web.getAttribute("href"), "https://dev.azure.com/acme/Proarc-Products/_git/web-app");
  // A javascript: URL from the source is shown as text, never a link.
  assert.ok(![...root.querySelectorAll("a")].some((a) => (a.getAttribute("href") || "").startsWith("javascript:")));
  assert.match(root.querySelector('a[href="#/scans/20261022T000000Z-web-feature"]').textContent, /Fails policy/);
  assert.deepEqual(await axe(dom), []);
});

test("repositories: the filter hides other repositories without a reload", async () => {
  const { dom, root, calls } = await boot("#/repositories", { repositories: repositories() });
  const before = calls.filter(([name]) => name === "repositories").length;
  const filter = root.querySelector('input[type="search"]');
  filter.value = "tools/";
  filter.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  const rows = [...root.querySelectorAll("tr[data-repo]")];
  assert.deepEqual(rows.filter((row) => !row.hidden).map((row) => row.getAttribute("data-repo")), ["tools/api"]);
  assert.equal(calls.filter(([name]) => name === "repositories").length, before);
});

test("repositories: an administrator starts a sync; a member cannot", async () => {
  const { root, calls } = await boot("#/repositories", { repositories: repositories() });
  const sync = [...root.querySelectorAll("button")].find((b) => b.textContent.includes("Sync now"));
  sync.click();
  await settle();
  assert.ok(calls.some(([name]) => name === "syncRepositories"));
  assert.match(text(root), /Sync started/);
  const member = { id: 2, provider: "entra", login: "bo@example.com", displayName: "Bo", role: "user" };
  const second = await boot("#/repositories", { session: { user: member }, repositories: repositories() });
  assert.ok(![...second.root.querySelectorAll("button")].some((b) => b.textContent.includes("Sync now")));
});

test("repositories: a failed sync keeps the last list and says why", async () => {
  const payload = repositories();
  payload.sources[1].error = "Azure DevOps did not list projects. HTTP 503.";
  const { root } = await boot("#/repositories", { repositories: payload });
  assert.match(text(root), /The last sync failed\..*HTTP 503\..*Showing the last good sync\./);
  assert.match(text(root), /web-app/);
});

test("repositories: nothing connected explains how to connect", async () => {
  const { dom, root } = await boot("#/repositories");
  assert.match(text(root), /No organization is connected/);
  assert.match(text(root), /CHECKSTEAD_AZURE_DEVOPS_ORG/);
  assert.deepEqual(await axe(dom), []);
});

test("CI runs: Azure DevOps pipeline runs sit beside GitHub", async () => {
  const runs = {
    syncing: false,
    sources: [
      {
        kind: "azure-devops", label: "Azure DevOps: acme", configured: true, syncedAt: "2026-10-22T06:00:00Z", error: null,
        runs: [{ source: "azure-devops", id: "130078", repository: "web-app", project: "Proarc-Products", pipeline: "checkstead-pr",
          status: "completed", result: "failed", branch: "feature/add-axios", url: "https://dev.azure.com/acme/x/_build/results?buildId=130078",
          queuedAt: "2026-10-22T06:00:00Z", finishedAt: "2026-10-22T06:09:00Z" }],
      },
    ],
  };
  const { dom, root } = await boot("#/builds", { runs });
  const page = text(root);
  assert.match(page, /Proarc-Products\/web-app/);
  assert.match(page, /checkstead-pr/);
  assert.match(page, /failed/);
  // GitHub is not connected but another source is: a note, not the full set-up panel.
  assert.match(page, /GitHub is not connected\. Set up the GitHub App to list workflow runs too\./);
  assert.deepEqual(await axe(dom), []);
});

test("members see neither the Access link nor the page", async () => {
  const member = { id: 2, provider: "github", login: "bo", displayName: "Bo", role: "user" };
  const { root, calls } = await boot("#/access", { session: { user: member } });
  assert.equal([...root.querySelectorAll(".rail a")].some((a) => a.textContent.includes("Access")), false);
  assert.match(text(root), /Only administrators manage access/);
  assert.ok(!calls.some(([name]) => name === "users"));
});
