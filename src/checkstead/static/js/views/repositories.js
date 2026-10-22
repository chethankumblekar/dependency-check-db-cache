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
  const admin = ctx.state.user && ctx.state.user.role === "admin";
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
      title: "No organization is connected",
      body: "Connect an Azure DevOps organization with CHECKSTEAD_AZURE_DEVOPS_ORG and the server's Microsoft Entra application, or install the Checkstead GitHub App. Repositories and branches then sync here on their own.",
      action: h("a", { class: "btn", href: "/github" }, "Set up the GitHub App"),
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
    const name = row.getAttribute("data-repo") || "";
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
    row.setAttribute("data-repo", `${flat[index].project || ""}/${flat[index].name}`.toLowerCase());
    index += 1;
  });
  return h(
    "section",
    { class: "panel", "aria-label": source.label },
    h("h2", null, source.label),
    h(
      "p",
      { class: "muted" },
      source.syncedAt ? h("span", null, "Synced ", timeEl(source.syncedAt, ctx.now)) : "Not synced yet",
      ` · ${source.repositories.length} repositories`,
    ),
    source.error ? banner("warn", "The last sync failed.", ` ${source.error}${source.syncedAt ? " Showing the last good sync." : ""}`) : null,
    table,
  );
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
  const tag = scan.failed
    ? h("span", { class: "tag fail" }, "Fails policy")
    : h("span", { class: "tag verified" }, scan.findings ? `Passes, ${scan.findings} findings` : "Passes, no findings");
  return h("a", { href: href("scan", { id: scan.id }) }, tag);
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
        ),
      ),
    ),
  );
}
