// @ts-check
// CI runs: Checkstead workflow runs the installed GitHub App can see.

import { banner, dataTable, stateBlock, timeEl } from "../components.js";
import { h, safeHttpUrl } from "../dom.js";
import { pageHead, withLoad } from "./common.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").BuildRuns} BuildRuns */
/** @typedef {import("../api.js").BuildRun} BuildRun */

/** @param {Context} ctx */
export function renderBuilds(ctx) {
  const refresh = h("button", { type: "button", class: "btn", onclick: () => ctx.load("builds", true) }, "Refresh");
  return h(
    "div",
    null,
    pageHead("CI runs", "Recent Checkstead workflow runs in the repositories the GitHub App can read.", refresh),
    withLoad(ctx, "builds", (/** @type {BuildRuns} */ runs) => builds(ctx, runs)),
  );
}

/**
 * @param {Context} ctx
 * @param {BuildRuns} payload
 */
function builds(ctx, payload) {
  if (!payload.connected) {
    return stateBlock({
      iconName: "builds",
      title: "GitHub is not connected",
      body: "Create and install the Checkstead GitHub App to list workflow runs and scan repositories from this server. It needs an administrator.",
      action: h("a", { class: "btn primary", href: "/github" }, "Set up the GitHub App"),
    });
  }
  const approval = safeHttpUrl(payload.approvalUrl);
  return h(
    "div",
    null,
    payload.notice ? h("div", null, banner("warn", payload.notice, ""), approval ? h("p", null, h("a", { class: "btn", href: approval, rel: "noopener noreferrer" }, "Approve on GitHub")) : null) : null,
    dataTable({
      caption: "Checkstead workflow runs",
      columns: [
        { key: "status", label: "Status", cell: (run) => statusTag(run) },
        { key: "repo", label: "Repository", cell: (run) => runLink(run) },
        { key: "ref", label: "Branch or pull request", cell: (run) => refCell(run) },
        { key: "updated", label: "Updated", cell: (run) => (run.updatedAt ? timeEl(run.updatedAt, ctx.now) : "not recorded") },
        { key: "action", label: "Action", cell: (run) => rerunButton(ctx, run) },
      ],
      groups: [{ label: null, rows: payload.runs }],
      empty: payload.notice ? "No runs can be listed until GitHub access is approved." : "No recent Checkstead workflow runs.",
    }),
  );
}

/** @param {BuildRun} run */
function statusTag(run) {
  const status = String(run.status || "unknown");
  const tone = /success|passed/i.test(status) ? "verified" : /fail|error|cancel/i.test(status) ? "warn" : "";
  return h("span", { class: `tag ${tone}`.trim() }, status);
}

/** @param {BuildRun} run */
function runLink(run) {
  const url = safeHttpUrl(run.url);
  const name = run.repository || run.name || "Workflow";
  return url ? h("a", { href: url, rel: "noopener noreferrer" }, name) : name;
}

/** @param {BuildRun} run */
function refCell(run) {
  if (run.pullRequest) {
    const url = safeHttpUrl(run.pullRequestUrl);
    return url ? h("a", { href: url, rel: "noopener noreferrer" }, `#${run.pullRequest}`) : `#${run.pullRequest}`;
  }
  return run.branch || "not recorded";
}

/**
 * @param {Context} ctx
 * @param {BuildRun} run
 */
function rerunButton(ctx, run) {
  const button = h("button", { type: "button", class: "btn" }, "Rerun");
  button.addEventListener("click", async () => {
    button.setAttribute("disabled", "");
    button.textContent = "Starting…";
    try {
      await ctx.api.rerun(run.repository || "", run.id);
      ctx.notify(`Rerun requested for ${run.repository || "the workflow"}.`);
      ctx.load("builds", true);
    } catch (error) {
      ctx.notify(`Rerun failed: ${/** @type {Error} */ (error).message}`);
      button.removeAttribute("disabled");
      button.textContent = "Rerun";
    }
  });
  return button;
}
