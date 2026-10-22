// Test helpers: a fresh jsdom document per test, a fake API, and fixture
// data. The fixtures are test data only; the app never ships sample data.
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const AXE_SOURCE = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");

/** Install a fresh DOM as the globals the app modules use. */
export function freshDom(hash = "#/") {
  const dom = new JSDOM('<!DOCTYPE html><html lang="en"><head><title>Checkstead</title></head><body><a class="skip" href="#main">Skip to content</a><div id="app"></div></body></html>', {
    url: `http://127.0.0.1:8765/${hash}`,
    pretendToBeVisual: true,
    runScripts: "outside-only",
  });
  const { window } = dom;
  Object.assign(globalThis, {
    window,
    document: window.document,
    HTMLElement: window.HTMLElement,
    HTMLInputElement: window.HTMLInputElement,
    HTMLSelectElement: window.HTMLSelectElement,
    Node: window.Node,
    Event: window.Event,
    KeyboardEvent: window.KeyboardEvent,
  });
  Object.defineProperty(globalThis, "navigator", { value: window.navigator, configurable: true });
  return dom;
}

/** Let promise callbacks and queued microtasks run. */
export async function settle(times = 6) {
  for (let i = 0; i < times; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

/** Run axe-core in the jsdom window. Contrast needs layout jsdom lacks, so it is checked by hand. */
export async function axe(dom) {
  if (!dom.window.axe) dom.window.eval(AXE_SOURCE);
  const result = await dom.window.axe.run(dom.window.document, {
    rules: { "color-contrast": { enabled: false } },
  });
  return [...result.violations].map((v) => `${v.id}: ${v.help} (${v.nodes.length})`);
}

export const NOW = new Date("2026-10-20T18:00:00Z");

/** @returns {any} */
export function finding(id, score, extra = {}) {
  return { id, dependency: extra.dependency || "lib.jar", cvss: { "3.1": "CVSS:3.1/AV:N" }, score: score === null ? undefined : String(score), scoreSource: "NVD", relationship: "direct", scope: "production", package: extra.package || "lib@1.0.0", description: `${id} description`, ...extra };
}

/** @returns {any} */
export function scan(id, extra = {}) {
  return {
    id,
    project: "payments",
    engine: "13.0.0",
    snapshot: "2026-10-20T05:32:17Z",
    checksum: "sha256:" + "a".repeat(64),
    revision: "99ee318d0d31aa",
    author: "Ada",
    authorEmail: "ada@example.com",
    hasDependencyReport: true,
    hasScoreSource: true,
    scoreLines: [],
    pullRequest: null,
    branch: "main",
    authenticity: "signed",
    signatureKey: "checkstead-2026-10",
    policy: { scorePolicy: "prefer-newest", threshold: "7", failOnKev: "true", failUnscored: "false" },
    dependencyCount: 2,
    findings: [],
    ...extra,
  };
}

export function history(extra = {}) {
  const before = scan("01-old", { snapshot: "2026-10-10T05:00:00Z", authenticity: null, signatureKey: null, findings: [finding("CVE-2020-0001", 5.3)] });
  const after = scan("02-new", {
    findings: [
      finding("CVE-2021-44228", 10.0, { kev: true, package: "log4j-core@2.14.1" }),
      finding("CVE-2015-6420", 9.8, { package: "commons-collections@3.2.1" }),
      finding("GHSA-35jh-r3h4-6jhm", 7.2, { relationship: "transitive", package: "lodash@4.17.15", scoreSource: "NPM" }),
      finding("CVE-2020-0001", 5.3),
      finding("GHSA-vcvr-r3jv-pc5j", null, { relationship: "direct", scope: "dev", package: "next@16.3.5" }),
    ],
  });
  return {
    notice: "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
    scans: [before, after],
    drifts: [
      {
        before: "01-old",
        after: "02-new",
        dependencyCounts: { added: 1, removed: 0, changed: 1 },
        findings: { added: [after.findings[0], after.findings[1]], removed: [], changed: [] },
        scores: { available: true },
      },
    ],
    ...extra,
  };
}

export function detail(id) {
  const data = history();
  const found = data.scans.find((item) => item.id === id);
  return {
    notice: data.notice,
    scan: { ...found, dependencies: [{ name: "log4j-core", version: "2.14.1", fileName: "log4j-core-2.14.1.jar", sha256: "b".repeat(64) }, { name: "lodash", version: "4.17.15", fileName: "lodash:4.17.15", sha256: "" }] },
    drift: id === "02-new" ? { ...data.drifts[0], dependencies: { added: [{ name: "log4j-core", version: "2.14.1", fileName: "log4j-core-2.14.1.jar", sha256: "" }], removed: [], changed: [{ before: { name: "lodash", version: "4.17.11", fileName: "", sha256: "" }, after: { name: "lodash", version: "4.17.15", fileName: "", sha256: "" } }] } } : null,
  };
}

/**
 * A fake API. Each method is replaceable; calls are recorded.
 * @param {Record<string, any>} overrides
 */
/** One synced Azure DevOps organization, as /api/repositories returns it. */
export function repositories(extra = {}) {
  const pass = { id: "20261022T000000Z-web-main", failed: false, findings: 2, revision: "a".repeat(40) };
  const fail = { id: "20261022T000000Z-web-feature", failed: true, findings: 32, revision: "b".repeat(40) };
  return {
    syncing: false,
    sources: [
      { kind: "github", label: "GitHub", configured: false, syncedAt: null, attemptedAt: null, error: null, repositories: [] },
      {
        kind: "azure-devops",
        label: "Azure DevOps: acme",
        configured: true,
        syncedAt: "2026-10-22T06:00:00Z",
        attemptedAt: "2026-10-22T06:00:00Z",
        error: null,
        repositories: [
          {
            source: "azure-devops", id: "r1", name: "web-app", project: "Proarc-Products",
            url: "https://dev.azure.com/acme/Proarc-Products/_git/web-app", defaultBranch: "main", disabled: false,
            branches: [
              { name: "feature/add-axios", commit: "b".repeat(40), scan: fail },
              { name: "main", commit: "a".repeat(40), scan: pass },
            ],
            defaultScan: pass,
          },
          {
            source: "azure-devops", id: "r2", name: "api", project: "Tools",
            url: "javascript:alert(1)", defaultBranch: "develop", disabled: false,
            branches: [{ name: "develop", commit: null, scan: null }],
            defaultScan: null,
          },
        ],
      },
    ],
    ...extra,
  };
}

export function fakeApi(overrides = {}) {
  const calls = [];
  const record = (name, value) => (...args) => {
    calls.push([name, ...args]);
    return typeof value === "function" ? value(...args) : Promise.resolve(value);
  };
  const user = { id: 1, provider: "github", login: "ada", displayName: "Ada Lovelace", role: "admin" };
  const base = {
    session: record("session", { user }),
    signInLocal: record("signInLocal", { user }),
    signOut: record("signOut", { signedOut: true }),
    sso: record("sso", { github: { enabled: true, start: "/api/sso/github/start" }, entra: { enabled: false, start: "/api/sso/entra/start", tenant: "organizations" }, local: { enabled: true } }),
    providers: record("providers", { providers: [], later: "" }),
    history: record("history", history()),
    scan: record("scan", (id) => Promise.resolve(detail(id))),
    users: record("users", { users: [user, { id: 2, provider: "entra", login: "bo@example.com", displayName: "Bo", role: "user" }] }),
    addUser: record("addUser", (body) => Promise.resolve({ user: { id: 3, displayName: body.login, ...body } })),
    setRole: record("setRole", (id, role) => Promise.resolve({ user: { ...user, id, role } })),
    removeUser: record("removeUser", (id) => Promise.resolve({ removed: id })),
    builds: record("builds", { connected: false, runs: [] }),
    rerun: record("rerun", {}),
    repositories: record("repositories", { syncing: false, sources: [] }),
    syncRepositories: record("syncRepositories", { started: true, syncing: true }),
    runs: record("runs", { syncing: false, sources: [] }),
  };
  for (const [name, value] of Object.entries(overrides)) base[name] = record(name, value);
  return { api: base, calls };
}

export function rejecting(error) {
  return () => Promise.reject(error);
}
