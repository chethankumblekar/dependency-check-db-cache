// @ts-check
// Scans: the timeline by branch, and one scan's findings, changes,
// dependencies, and evidence.

import { dataTable, errorState, evidenceChain, kevTag, kv, segmented, severityMark, skeleton, stateBlock, tabs, timeEl } from "../components.js";
import { h, safeHttpUrl } from "../dom.js";
import { freshness, plural, scanName, severity, shortDigest, utcLabel } from "../format.js";
import { branchGroups, driftInto, evidenceChain as chainFor, findingKey, packageLabel, severityCounts } from "../model.js";
import { href } from "../router.js";
import { pageHead, withLoad } from "./common.js";
import { dataTag, signatureTag } from "./overview.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").History} History */
/** @typedef {import("../api.js").Scan} Scan */
/** @typedef {import("../api.js").Finding} Finding */
/** @typedef {import("../api.js").Dependency} Dependency */

/** @param {Context} ctx */
export function renderScans(ctx) {
  return withLoad(ctx, "history", (/** @type {History} */ history) => {
    if (!history.scans.length) {
      return h("div", null, pageHead("Scans"), stateBlock({ iconName: "scans", title: "No scans yet", body: "Scan reports appear here once a scan writes into this server's scan directory." }));
    }
    // No scan chosen: open the newest one rather than an empty pane.
    const newest = history.scans[history.scans.length - 1];
    return layout(ctx, history, newest.id, scanDetail(ctx, history, newest));
  });
}

/** @param {Context} ctx */
export function renderScan(ctx) {
  return withLoad(ctx, "history", (/** @type {History} */ history) => {
    const scan = history.scans.find((item) => item.id === ctx.route.params.id);
    if (!scan) {
      return h("div", null, pageHead("Scan not found"), stateBlock({ iconName: "alert", title: "There is no scan with that name", body: "It may have been removed from the scan directory.", action: h("a", { class: "btn", href: href("scans") }, "See all scans") }));
    }
    return layout(ctx, history, scan.id, scanDetail(ctx, history, scan));
  });
}

/**
 * A scan directory name, shortened for the list: CI names end in the run id.
 * @param {string} id
 */
function scanLabel(id) {
  return id.length > 34 ? `…${id.slice(-32)}` : id;
}

/**
 * @param {Context} ctx
 * @param {History} history
 * @param {string} currentId
 * @param {Node} detail
 */
function layout(ctx, history, currentId, detail) {
  const list = h(
    "nav",
    { class: "scan-list", "aria-label": "Scans by branch" },
    branchGroups(history.scans).map((group) =>
      h(
        "section",
        null,
        h("h2", null, group.branch ? `Branch ${group.branch}` : "Branch not recorded"),
        h(
          "ul",
          null,
          group.scans.map((scan) => {
            const counts = severityCounts(scan.findings || []);
            return h(
              "li",
              null,
              h(
                "a",
                { href: href("scan", { id: scan.id }), "aria-current": scan.id === currentId ? "true" : null },
                h("strong", null, scanName(scan)),
                h("span", { class: "meta" }, scan.revision ? h("span", { class: "id" }, scan.revision.slice(0, 7)) : h("span", { class: "id" }, scanLabel(scan.id)), ` · ${plural(counts.total, "finding")}${counts.kev ? `, ${counts.kev} exploited` : ""}`),
                h("span", { class: "meta" }, "Snapshot ", timeEl(scan.snapshot, ctx.now)),
              ),
            );
          }),
        ),
      ),
    ),
  );
  return h("div", { class: "split" }, list, h("div", null, detail));
}

/**
 * @param {Context} ctx
 * @param {History} history
 * @param {Scan} scan
 */
function scanDetail(ctx, history, scan) {
  const tab = ctx.route.params.tab || "findings";
  const drift = driftInto(history, scan.id);
  const lead = [
    scan.branch ? `Branch ${scan.branch}` : "Branch not recorded",
    scan.revision ? `revision ${scan.revision.slice(0, 12)}` : "revision not recorded",
    scan.author ? `committed by ${scan.author}` : null,
  ].filter(Boolean).join(", ");
  const panel =
    tab === "changes"
      ? withScan(ctx, scan, (detail) => changes(detail.drift || undefined))
      : tab === "dependencies"
        ? withScan(ctx, scan, (detail) => dependencies(ctx, detail.scan))
        : tab === "evidence"
          ? evidence(ctx, scan)
          : findings(ctx, scan);
  const dependencyCount = scan.dependencyCount ?? (scan.dependencies || []).length;
  return h(
    "div",
    null,
    pageHead(scanName(scan), `${lead}.`, h("div", { class: "toolbar" }, dataTag(scan, ctx.now), signatureTag(scan))),
    tabs(
      "Scan sections",
      [
        { id: "findings", text: `Findings (${(scan.findings || []).length})`, href: href("scan", { id: scan.id }) },
        { id: "changes", text: drift ? `Changes (${drift.findings.added.length + drift.findings.removed.length + drift.findings.changed.length})` : "Changes", href: href("scan", { id: scan.id, tab: "changes" }) },
        { id: "dependencies", text: `Dependencies (${dependencyCount})`, href: href("scan", { id: scan.id, tab: "dependencies" }) },
        { id: "evidence", text: "Evidence", href: href("scan", { id: scan.id, tab: "evidence" }) },
      ],
      tab,
    ),
    h("div", { id: "tab-panel", role: "tabpanel", "aria-labelledby": `tab-${tab}` }, panel),
  );
}

/**
 * The full scan for tabs that need dependency lists, loaded on first use.
 * @param {Context} ctx
 * @param {Scan} scan
 * @param {(detail: import("../api.js").ScanDetail) => Node} ready
 */
function withScan(ctx, scan, ready) {
  const slot = ctx.scanDetail(scan.id);
  if (slot.status === "ready" && slot.data) return ready(slot.data);
  if (slot.status === "error" && slot.error) {
    return errorState(slot.error, () => {
      ctx.state.scans.delete(scan.id);
      ctx.render();
    });
  }
  return skeleton(5);
}

const GROUPS = /** @type {const} */ ([
  ["direct", "production", "Direct, production"],
  ["direct", "dev", "Direct, development"],
  ["transitive", "production", "Transitive, production"],
  ["transitive", "dev", "Transitive, development"],
]);

/**
 * @param {Finding} finding
 * @param {string} key
 * @returns {string | number}
 */
function sortValue(finding, key) {
  if (key === "score") {
    const value = Number(finding.score);
    return Number.isFinite(value) ? value : -1;
  }
  if (key === "package") return packageLabel(finding);
  if (key === "source") return finding.scoreSource || "";
  return finding.id || "";
}

/**
 * @param {Context} ctx
 * @param {Scan} scan
 */
function findings(ctx, scan) {
  const filters = ctx.state.findings;
  const all = scan.findings || [];
  if (!all.length) {
    return stateBlock({ iconName: "check", title: "No findings", body: "Dependency-Check matched no known vulnerability in this scan's dependencies, using the snapshot shown under Evidence." });
  }
  const query = filters.query.trim().toLowerCase();
  const visible = all.filter((finding) => {
    if (filters.relationship && (finding.relationship || "direct") !== filters.relationship) return false;
    if (filters.scope && (finding.scope || "production") !== filters.scope) return false;
    if (filters.kevOnly && !finding.kev) return false;
    if (query && !`${finding.id} ${packageLabel(finding)} ${finding.description || ""}`.toLowerCase().includes(query)) return false;
    return true;
  });
  visible.sort((a, b) => {
    const left = sortValue(a, filters.sort);
    const right = sortValue(b, filters.sort);
    const order = typeof left === "number" && typeof right === "number" ? left - right : String(left).localeCompare(String(right));
    return (filters.descending ? -order : order) || String(a.id).localeCompare(String(b.id));
  });
  if (!visible.some((finding) => findingKey(finding) === filters.selected)) filters.selected = visible.length ? findingKey(visible[0]) : null;
  const selected = visible.find((finding) => findingKey(finding) === filters.selected) || null;

  /** @param {Partial<typeof filters>} change */
  const update = (change) => {
    Object.assign(filters, change);
    ctx.render();
  };
  const search = h("input", { type: "search", placeholder: "Filter by id, package, or text", "aria-label": "Filter findings", value: filters.query });
  search.addEventListener("input", () => {
    filters.query = /** @type {HTMLInputElement} */ (search).value;
    const position = /** @type {HTMLInputElement} */ (search).selectionStart;
    ctx.render();
    const next = document.querySelector('input[aria-label="Filter findings"]');
    if (next instanceof HTMLInputElement) {
      next.focus();
      next.setSelectionRange(position, position);
    }
  });
  const kevCount = all.filter((finding) => finding.kev).length;
  /** @type {{label: string, rows: Finding[]}[]} */
  const groups = GROUPS.map(([relationship, scope, label]) => ({
    label,
    rows: visible.filter((finding) => (finding.relationship || "direct") === relationship && (finding.scope || "production") === scope),
  }));
  const known = new Set(groups.flatMap((group) => group.rows));
  groups.push({ label: "Other", rows: visible.filter((finding) => !known.has(finding)) });

  return h(
    "div",
    null,
    h(
      "div",
      { class: "toolbar" },
      search,
      segmented("Relationship", [["", "All"], ["direct", "Direct"], ["transitive", "Transitive"]], filters.relationship, (value) => update({ relationship: value })),
      segmented("Scope", [["", "All"], ["production", "Production"], ["dev", "Development"]], filters.scope, (value) => update({ scope: value })),
      kevCount ? segmented("Exploited", [["", "All"], ["kev", `Exploited (${kevCount})`]], filters.kevOnly ? "kev" : "", (value) => update({ kevOnly: value === "kev" })) : null,
      h("span", { class: "muted small", role: "status" }, `${visible.length} of ${plural(all.length, "finding")}`),
    ),
    dataTable({
      caption: `Findings in ${scanName(scan)}`,
      tall: true,
      columns: [
        { key: "score", label: "Severity", sortable: true, cell: (finding) => severityMark(finding.score) },
        { key: "id", label: "Vulnerability", sortable: true, cell: (finding) => h("span", null, h("span", { class: "id" }, finding.id), finding.kev ? " " : null, finding.kev ? kevTag() : null) },
        { key: "package", label: "Package", sortable: true, cell: (finding) => h("span", { class: "id" }, packageLabel(finding)) },
        { key: "source", label: "Score source", sortable: true, cell: (finding) => finding.scoreSource || "none" },
      ],
      groups,
      sort: { key: filters.sort, descending: filters.descending },
      onSort: (key) => update(filters.sort === key ? { descending: !filters.descending } : { sort: key, descending: key === "score" }),
      rowKey: findingKey,
      selected: filters.selected,
      onSelect: (finding) => update({ selected: findingKey(finding) }),
      empty: "No findings match these filters.",
    }),
    selected ? findingDetail(selected) : null,
  );
}

/** @param {Finding} finding */
function advisoryUrl(finding) {
  if (/^CVE-\d{4}-\d+$/.test(finding.id)) return safeHttpUrl(`https://nvd.nist.gov/vuln/detail/${finding.id}`);
  if (/^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/.test(finding.id)) return safeHttpUrl(`https://github.com/advisories/${finding.id}`);
  return "";
}

/** @param {Finding} finding */
function findingDetail(finding) {
  const band = severity(finding.score);
  const url = advisoryUrl(finding);
  const vectors = Object.entries(finding.cvss || {}).map(([version, vector]) => h("div", { class: "id small" }, `CVSS ${version}: ${vector}`));
  const advice = [
    finding.kev ? "This vulnerability is being exploited. Treat it as an incident-level fix." : null,
    `Upgrade ${packageLabel(finding)} to a release the advisory lists as fixed.`,
    (finding.relationship || "direct") === "transitive" ? "It is a transitive dependency: upgrade the direct dependency that brings it in, or pin the fixed version in your lockfile." : null,
    "If the vulnerable code is not reachable, record that as a suppression with an expiry date instead of ignoring it.",
  ].filter(Boolean);
  return h(
    "section",
    { class: "panel finding-detail", "aria-labelledby": "finding-head", "aria-live": "polite" },
    h("h2", { id: "finding-head" }, h("span", { class: "id" }, finding.id), " in ", h("span", { class: "id" }, packageLabel(finding))),
    h("p", null, finding.description || "No description recorded."),
    kv([
      ["Severity", band === "none" ? "No score recorded" : `${severityMark(finding.score).textContent} (CVSS)`],
      ["Score source", finding.scoreSource || "none"],
      ["Relationship", `${finding.relationship || "direct"}, ${finding.scope || "production"}`],
      ["Exploited", finding.kev === true ? "Yes, on the CISA KEV list" : finding.kev === false ? "No" : "Not recorded"],
      ["Vectors", vectors.length ? h("div", null, vectors) : "None recorded"],
      ["Advisory", url ? h("a", { href: url, rel: "noopener noreferrer", target: "_blank" }, url.replace(/^https:\/\//, "")) : "No public link for this identifier"],
    ]),
    h("h3", null, "What to do"),
    h("ul", null, advice.map((line) => h("li", null, line))),
  );
}

/**
 * Most severe first; unscored last.
 * @param {Finding[]} items
 */
function bySeverity(items) {
  const rank = (/** @type {Finding} */ finding) => {
    const value = Number(finding.score);
    return Number.isFinite(value) ? value : -1;
  };
  return [...items].sort((a, b) => rank(b) - rank(a) || String(a.id).localeCompare(String(b.id)));
}

/** @param {import("../api.js").Drift | undefined} drift */
function changes(drift) {
  if (!drift) {
    return stateBlock({ iconName: "clock", title: "First scan on this branch", body: "Changes appear once the branch has a later scan to compare with." });
  }
  const f = drift.findings;
  const d = drift.dependencies || { added: [], removed: [], changed: [] };
  if (!f.added.length && !f.removed.length && !f.changed.length && !d.added.length && !d.removed.length && !d.changed.length) {
    return stateBlock({ iconName: "check", title: "Nothing changed", body: "Findings and dependencies are the same as in the previous scan on this branch." });
  }
  /** @type {import("../components.js").Column<{kind: string, finding: Finding}>[]} */
  const findingColumns = [
    { key: "kind", label: "Change", cell: (row) => row.kind },
    { key: "score", label: "Severity", cell: (row) => severityMark(row.finding.score) },
    { key: "id", label: "Vulnerability", cell: (row) => h("span", { class: "id" }, row.finding.id) },
    { key: "package", label: "Package", cell: (row) => h("span", { class: "id" }, packageLabel(row.finding)) },
  ];
  /** @type {import("../components.js").Column<{kind: string, before: Dependency | null, after: Dependency | null}>[]} */
  const dependencyColumns = [
    { key: "kind", label: "Change", cell: (row) => row.kind },
    { key: "name", label: "Dependency", cell: (row) => h("span", { class: "id" }, (row.after || row.before)?.name || "") },
    { key: "before", label: "Before", cell: (row) => row.before?.version || "—" },
    { key: "after", label: "After", cell: (row) => row.after?.version || "—" },
  ];
  return h(
    "div",
    null,
    !drift.scores.available ? h("p", { class: "muted small" }, "These reports carry no score source, so score changes are not compared.") : null,
    h("h2", null, "Findings"),
    dataTable({
      caption: "Finding changes since the previous scan",
      columns: findingColumns,
      groups: [
        { label: "Introduced", rows: bySeverity(f.added).map((finding) => ({ kind: "New", finding })) },
        { label: "Changed", rows: bySeverity(f.changed.map((pair) => pair.after)).map((finding) => ({ kind: "Changed", finding })) },
        { label: "Resolved", rows: bySeverity(f.removed).map((finding) => ({ kind: "Resolved", finding })) },
      ],
      empty: "No finding changed.",
    }),
    h("h2", { style: null }, "Dependencies"),
    dataTable({
      caption: "Dependency changes since the previous scan",
      columns: dependencyColumns,
      groups: [
        { label: "Added", rows: d.added.slice(0, DEPENDENCY_ROWS).map((item) => ({ kind: "Added", before: null, after: item })) },
        { label: "Changed", rows: d.changed.slice(0, DEPENDENCY_ROWS).map((pair) => ({ kind: "Changed", before: pair.before, after: pair.after })) },
        { label: "Removed", rows: d.removed.slice(0, DEPENDENCY_ROWS).map((item) => ({ kind: "Removed", before: item, after: null })) },
      ],
      empty: "No dependency changed.",
    }),
    Math.max(d.added.length, d.changed.length, d.removed.length) > DEPENDENCY_ROWS
      ? h("p", { class: "muted small" }, `Each group shows its first ${DEPENDENCY_ROWS} entries: ${d.added.length} added, ${d.changed.length} changed, ${d.removed.length} removed in total.`)
      : null,
  );
}

const DEPENDENCY_ROWS = 500;

/**
 * @param {Context} ctx
 * @param {Scan} scan
 */
function dependencies(ctx, scan) {
  const items = scan.dependencies || [];
  if (!scan.hasDependencyReport) {
    return stateBlock({ iconName: "alert", title: "No dependency report", body: "This scan directory has no dependency-check-report.json, so its dependencies are unknown." });
  }
  const filters = ctx.state.dependencies;
  const query = filters.query.trim().toLowerCase();
  const matching = query ? items.filter((item) => `${item.name} ${item.version} ${item.fileName}`.toLowerCase().includes(query)) : items;
  // A tree with node_modules can list tens of thousands; rendering them all
  // freezes the page, so only the first rows are drawn and the count says so.
  const shown = matching.slice(0, DEPENDENCY_ROWS);
  const search = h("input", { type: "search", placeholder: "Filter by name, version, or file", "aria-label": "Filter dependencies", value: filters.query });
  search.addEventListener("input", () => {
    filters.query = /** @type {HTMLInputElement} */ (search).value;
    const position = /** @type {HTMLInputElement} */ (search).selectionStart;
    ctx.render();
    const next = document.querySelector('input[aria-label="Filter dependencies"]');
    if (next instanceof HTMLInputElement) {
      next.focus();
      next.setSelectionRange(position, position);
    }
  });
  return h(
    "div",
    null,
    h(
      "div",
      { class: "toolbar" },
      search,
      h("span", { class: "muted small", role: "status" }, shown.length < matching.length ? `Showing the first ${shown.length} of ${matching.length}. Filter to narrow it down.` : `${plural(matching.length, "dependency", "dependencies")}`),
    ),
    dataTable({
      caption: `Dependencies in ${scanName(scan)}`,
      tall: true,
      columns: [
        { key: "name", label: "Name", cell: (item) => h("span", { class: "id" }, item.name || item.fileName) },
        { key: "version", label: "Version", cell: (item) => item.version || "—" },
        { key: "file", label: "File", cell: (item) => item.fileName || "—" },
        { key: "sha", label: "SHA-256", cell: (item) => h("span", { class: "id", title: item.sha256 || "" }, shortDigest(item.sha256)) },
      ],
      groups: [{ label: null, rows: shown }],
      empty: query ? "No dependency matches this filter." : "Dependency-Check found no dependencies.",
    }),
  );
}

/**
 * @param {Context} ctx
 * @param {Scan} scan
 */
function evidence(ctx, scan) {
  const fresh = freshness(scan.snapshot, ctx.now);
  const policy = scan.policy || {};
  return h(
    "div",
    null,
    evidenceChain(chainFor(scan, ctx.now), `Evidence for ${scanName(scan)}`),
    h(
      "div",
      { class: "grid-2" },
      h(
        "section",
        { class: "panel", "aria-labelledby": "snapshot-head" },
        h("h2", { id: "snapshot-head" }, "Vulnerability data"),
        kv([
          ["Snapshot time", h("span", null, utcLabel(scan.snapshot), " (", timeEl(scan.snapshot, ctx.now), ")")],
          ["Freshness", fresh.freshness === "unknown" ? "Not recorded" : `${fresh.freshness}, ${fresh.age === 0 ? "from today" : plural(fresh.age || 0, "day") + " old"} (stale after 7)`],
          ["Zip digest", h("span", { class: "id" }, scan.checksum || "not recorded")],
          ["Signature", scan.authenticity === "signed" ? `Verified with key ${scan.signatureKey || "not named"}` : scan.authenticity === "unsigned" ? "Not verified. The scan accepted an unsigned snapshot." : "Not recorded in this report"],
          ["Engine", scan.engine ? `Dependency-Check ${scan.engine}` : "Not recorded"],
        ]),
      ),
      h(
        "section",
        { class: "panel", "aria-labelledby": "policy-head" },
        h("h2", { id: "policy-head" }, "Policy this scan applied"),
        Object.keys(policy).length
          ? kv([
              ["Score policy", policy.scorePolicy || "not recorded"],
              ["Fail at score", policy.threshold && policy.threshold !== "none" ? policy.threshold : "No threshold"],
              ["Fail on exploited", yesNo(policy.failOnKev)],
              ["Fail when unscored", yesNo(policy.failUnscored)],
            ])
          : h("p", { class: "muted" }, "This report does not record its policy."),
        h("h2", null, "Check it yourself"),
        h("p", { class: "small muted" }, "Rerun the scan client's checks on the machine that scanned:"),
        h("pre", { class: "id small" }, "checkstead doctor\ncheckstead scan --scan . --dry-run"),
      ),
    ),
  );
}

/**
 * A policy switch as the report records it, said in words.
 * @param {string | undefined} value
 */
function yesNo(value) {
  if (value === "true") return "Yes";
  if (value === "false") return "No";
  return value || "not recorded";
}
