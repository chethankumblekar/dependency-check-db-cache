// @ts-check
// Repositories and branches synced from the connected organizations, each with
// its newest Checkstead result. Scans from local checkouts stay on Scans.

import { banner, dataTable, stateBlock, timeEl } from "../components.js";
import { h, icon, safeHttpUrl } from "../dom.js";
import { href } from "../router.js";
import { pageHead, withLoad } from "./common.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").Repositories} Repositories */
/** @typedef {import("../api.js").RepositorySource} RepositorySource */
/** @typedef {import("../api.js").SourceRepository} SourceRepository */
/** @typedef {import("../api.js").BranchScan} BranchScan */

const POLL_MS = 3000;
/** @type {ReturnType<typeof setTimeout> | null} */
let poll = null;

/** @param {Context} ctx */
export function renderRepositories(ctx) {
  const admin = ctx.state.user?.role === "admin";
  const actions = h(
    "div",
    { class: "actions" },
    admin ? syncButton(ctx) : null,
    h("button", { type: "button", class: "btn", onclick: () => ctx.load("repositories", true) }, "Refresh"),
  );
  return h(
    "div",
    null,
    pageHead("Repositories", "Repositories and branches from the connected organizations, with each branch's newest Checkstead result. Scans of local checkouts stay on Scans.", actions),
    withLoad(ctx, "repositories", (/** @type {Repositories} */ payload) => repositories(ctx, payload)),
  );
}

/** @param {Context} ctx */
function syncButton(ctx) {
  const button = h("button", { type: "button", class: "btn primary" }, icon("sync"), "Sync now");
  button.addEventListener("click", async () => {
    button.setAttribute("disabled", "");
    try {
      await ctx.api.syncRepositories();
      ctx.notify("Sync started. The list updates when it finishes.");
      ctx.load("repositories", true);
    } catch (error) {
      ctx.notify(`Sync failed to start: ${/** @type {Error} */ (error).message}`);
      button.removeAttribute("disabled");
    }
  });
  return button;
}

/**
 * @param {Context} ctx
 * @param {Repositories} payload
 */
function repositories(ctx, payload) {
  if (poll) clearTimeout(poll);
  poll = payload.syncing ? setTimeout(() => ctx.load("repositories", true), POLL_MS) : null;
  const connected = payload.sources.filter((source) => source.configured);
  if (!connected.length) {
    return stateBlock({
      iconName: "repos",
      title: "No pipeline has sent a report yet",
      body: "Repositories appear here when their pipeline runs Checkstead and sends the report, the way SonarQube learns a repository from its analyses. Create an upload token on Access, store it as the secret variable CHECKSTEAD_UPLOAD_TOKEN, and set CHECKSTEAD_SERVER. Scans of local checkouts stay on Scans.",
      action: h("a", { class: "btn", href: href("access") }, "Create an upload token"),
    });
  }
  const filter = h("input", {
    type: "search",
    class: "input",
    placeholder: "Filter repositories",
    "aria-label": "Filter repositories",
    oninput: (/** @type {Event} */ event) => applyFilter(/** @type {HTMLInputElement} */ (event.target)),
  });
  return h(
    "div",
    null,
    payload.syncing ? banner("info", "Syncing", " Repositories and branches are being read from the connected organizations.") : null,
    h("p", null, filter),
    connected.map((source) => sourceSection(ctx, source)),
  );
}

/** @param {HTMLInputElement} input */
function applyFilter(input) {
  const query = input.value.trim().toLowerCase();
  const root = input.closest("main") || document;
  root.querySelectorAll("tr[data-repo]").forEach((row) => {
    const name = row instanceof HTMLElement ? row.dataset.repo || "" : "";
    row.toggleAttribute("hidden", Boolean(query) && !name.includes(query));
  });
}

/**
 * @param {Context} ctx
 * @param {RepositorySource} source
 */
function sourceSection(ctx, source) {
  /** @type {Map<string, SourceRepository[]>} */
  const byProject = new Map();
  for (const repo of source.repositories) {
    const key = repo.project || "";
    byProject.set(key, [...(byProject.get(key) || []), repo]);
  }
  const groups = [...byProject.entries()].map(([label, rows]) => ({ label: label || null, rows }));
  const table = dataTable({
    caption: `${source.label} repositories`,
    columns: [
      { key: "name", label: "Repository", cell: (repo) => repoCell(repo) },
      { key: "default", label: "Default branch", cell: (repo) => repo.defaultBranch || "none" },
      { key: "status", label: "Newest result", cell: (repo) => scanTag(repo.defaultScan, repo.defaultBranch) },
      { key: "branches", label: "Branches", cell: (repo) => branchList(repo) },
    ],
    groups,
    empty: source.syncedAt ? "The organization has no repositories this server can read." : "Not synced yet.",
  });
  // Tag each row with its repository name, for the filter.
  const rows = table.querySelectorAll("tbody tr");
  let index = 0;
  const flat = groups.flatMap((group) => group.rows);
  rows.forEach((row) => {
    if (row.querySelector("th.group") || !flat[index]) return;
    if (row instanceof HTMLElement) row.dataset.repo = `${flat[index].project || ""}/${flat[index].name}`.toLowerCase();
    index += 1;
  });
  return h(
    "section",
    { class: "panel", "aria-label": source.label },
    h("h2", null, source.label),
    h(
      "p",
      { class: "muted" },
      sourceMeta(ctx, source),
      ` · ${source.repositories.length} ${source.repositories.length === 1 ? "repository" : "repositories"}`,
    ),
    source.error ? syncError(source) : null,
    table,
  );
}

/** @param {RepositorySource} source */
function syncError(source) {
  const kept = source.syncedAt ? " Showing the last good sync." : "";
  return banner("warn", "The last sync failed.", ` ${source.error}${kept}`);
}

/**
 * @param {Context} ctx
 * @param {RepositorySource} source
 */
function sourceMeta(ctx, source) {
  if (source.reported) return "Reported by pipelines";
  return source.syncedAt ? h("span", null, "Synced ", timeEl(source.syncedAt, ctx.now)) : "Not synced yet";
}

/** @param {SourceRepository} repo */
function repoCell(repo) {
  const url = safeHttpUrl(repo.url);
  const name = url ? h("a", { href: url, rel: "noopener noreferrer" }, repo.name) : h("span", null, repo.name);
  return repo.disabled ? h("span", null, name, " ", h("span", { class: "tag" }, "disabled")) : name;
}

/**
 * @param {BranchScan | null} scan
 * @param {string | null} [branch]
 */
function scanTag(scan, branch) {
  if (!branch) return h("span", { class: "muted" }, "no branch");
  if (!scan) return h("span", { class: "muted" }, "not scanned");
  if (scan.failed) return h("a", { href: href("scan", { id: scan.id }) }, h("span", { class: "tag fail" }, "Fails policy"));
  const passes = scan.findings ? `Passes, ${scan.findings} findings` : "Passes, no findings";
  return h("a", { href: href("scan", { id: scan.id }) }, h("span", { class: "tag verified" }, passes));
}

/** @param {BranchScan | null} scan */
function runLink(scan) {
  const url = scan ? safeHttpUrl(scan.buildUrl) : null;
  return url ? h("a", { href: url, rel: "noopener noreferrer" }, "pipeline run") : null;
}

/** @param {SourceRepository} repo */
function branchList(repo) {
  if (!repo.branches.length) return h("span", { class: "muted" }, repo.disabled ? "not read" : "none");
  return h(
    "details",
    null,
    h("summary", null, `${repo.branches.length} ${repo.branches.length === 1 ? "branch" : "branches"}`),
    h(
      "ul",
      { class: "branch-list" },
      repo.branches.map((branch) =>
        h(
          "li",
          null,
          h("code", { class: "id" }, branch.name),
          branch.commit ? h("span", { class: "muted" }, ` ${branch.commit.slice(0, 8)} `) : " ",
          scanTag(branch.scan, branch.name),
          branch.scan && branch.scan.pullRequest ? h("span", { class: "tag" }, `PR #${branch.scan.pullRequest}`) : null,
          runLink(branch.scan),
        ),
      ),
    ),
  );
}
