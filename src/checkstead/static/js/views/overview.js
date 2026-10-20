// @ts-check
// Overview: can the newest data be trusted, and what needs a person now.

import { attentionList, banner, dataTable, evidenceChain, severityMark, stateBlock, timeEl } from "../components.js";
import { h } from "../dom.js";
import { freshness, plural, scanName } from "../format.js";
import { attention, evidenceChain as chainFor, latestScans, severityCounts } from "../model.js";
import { href } from "../router.js";
import { pageHead, withLoad } from "./common.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").History} History */
/** @typedef {import("../api.js").Scan} Scan */

/** @param {Context} ctx */
export function renderOverview(ctx) {
  return h(
    "div",
    null,
    pageHead("Overview", "The newest scan of each project and branch, and what it needs from you."),
    withLoad(ctx, "history", (/** @type {History} */ history) => overview(ctx, history)),
  );
}

/**
 * @param {Context} ctx
 * @param {History} history
 */
function overview(ctx, history) {
  if (!history.scans.length) return emptyOverview();
  const latest = latestScans(history.scans);
  const newest = history.scans[history.scans.length - 1];
  const items = attention(history, ctx.now);
  const findings = latest.flatMap((scan) => scan.findings || []);
  const counts = severityCounts(findings);
  const stale = latest.filter((scan) => freshness(scan.snapshot, ctx.now).freshness === "stale");

  return h(
    "div",
    null,
    stale.length ? banner("warn", `${plural(stale.length, "project")} scanned with stale data.`, " Their results miss vulnerabilities published since their snapshot.") : null,
    h(
      "section",
      { class: "section", "aria-labelledby": "evidence-head" },
      h("h2", { id: "evidence-head" }, "Evidence for the newest scan"),
      h("p", { class: "muted small" }, `${scanName(newest)}, snapshot `, timeEl(newest.snapshot, ctx.now), ". ", h("a", { href: href("scan", { id: newest.id, tab: "evidence" }) }, "See the evidence")),
      evidenceChain(chainFor(newest, ctx.now), `Evidence for ${scanName(newest)}`),
    ),
    h(
      "section",
      { class: "section", "aria-labelledby": "attention-head" },
      h("h2", { id: "attention-head" }, "Needs attention"),
      items.length ? attentionList(items) : stateBlock({ iconName: "check", title: "Nothing needs attention", body: "No exploited, critical, or new findings, no stale data, and no unverified snapshots in the newest scans." }),
    ),
    h(
      "section",
      { class: "section", "aria-labelledby": "posture-head" },
      h("h2", { id: "posture-head" }, "Findings in the newest scans"),
      h(
        "ul",
        { class: "counts" },
        countItem(counts.kev, "Exploited", "sev-critical"),
        countItem(counts.critical, "Critical", "sev-critical"),
        countItem(counts.high, "High", "sev-high"),
        countItem(counts.medium, "Medium", "sev-medium"),
        countItem(counts.low, "Low", "sev-low"),
        countItem(counts.none, "No score", "sev-none"),
      ),
      projectsTable(latest, ctx),
    ),
  );
}

/**
 * @param {number} value
 * @param {string} label
 * @param {string} tone
 */
function countItem(value, label, tone) {
  // Zero is not an alarm: it keeps the neutral ink colour.
  return h("li", { class: value ? tone : null }, h("span", { class: "n" }, String(value)), h("span", { class: "l" }, label));
}

/**
 * @param {Scan[]} latest
 * @param {Context} ctx
 */
function projectsTable(latest, ctx) {
  return dataTable({
    caption: "Newest scan per project and branch",
    columns: [
      { key: "project", label: "Project", cell: (scan) => h("a", { href: href("scan", { id: scan.id }) }, scanName(scan)) },
      { key: "branch", label: "Branch", cell: (scan) => scan.branch || "not recorded" },
      { key: "worst", label: "Highest", cell: (scan) => worst(scan) },
      { key: "count", label: "Findings", numeric: true, cell: (scan) => String((scan.findings || []).length) },
      { key: "kev", label: "Exploited", numeric: true, cell: (scan) => String(severityCounts(scan.findings || []).kev) },
      { key: "data", label: "Data", cell: (scan) => dataTag(scan, ctx.now) },
      { key: "signature", label: "Signature", cell: (scan) => signatureTag(scan) },
    ],
    groups: [{ label: null, rows: latest }],
  });
}

/** @param {Scan} scan */
function worst(scan) {
  const scores = (scan.findings || []).map((finding) => Number(finding.score)).filter(Number.isFinite);
  if (!scores.length) return h("span", { class: "muted" }, (scan.findings || []).length ? "No score" : "None");
  return severityMark(String(Math.max(...scores)));
}

/**
 * @param {Scan} scan
 * @param {Date} now
 */
export function dataTag(scan, now) {
  const fresh = freshness(scan.snapshot, now);
  const tone = fresh.freshness === "current" ? "verified" : fresh.freshness === "unknown" ? "" : "warn";
  const text = fresh.freshness === "unknown" ? "Not recorded" : `${fresh.freshness[0].toUpperCase()}${fresh.freshness.slice(1)}, ${fresh.age === 0 ? "today" : plural(fresh.age || 0, "day")}`;
  return h("span", { class: `tag ${tone}`.trim(), title: `Snapshot ${scan.snapshot}` }, text);
}

/** @param {Scan} scan */
export function signatureTag(scan) {
  if (scan.authenticity === "signed") return h("span", { class: "tag verified", title: `Key ${scan.signatureKey || "not named"}` }, "Verified");
  if (scan.authenticity === "unsigned") return h("span", { class: "tag warn" }, "Not verified");
  return h("span", { class: "tag", title: "This report predates signature recording." }, "Not recorded");
}

function emptyOverview() {
  return stateBlock({
    iconName: "scans",
    title: "No scans yet",
    body: "The timeline fills in as scan reports reach this server: from the GitHub Action, the Maven, Gradle, or Azure DevOps integrations, or `checkstead scan` with --out pointing at the scan directory.",
    action: h("a", { class: "btn", href: href("builds") }, "Connect GitHub"),
  });
}

