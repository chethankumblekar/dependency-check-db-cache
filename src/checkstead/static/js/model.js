// @ts-check
// Everything the views show is derived here from the server's history. No
// value is invented: when the reports do not record something, the result
// says "unknown" and the view says so.

import { freshness, plural, scanName, severity } from "./format.js";

/** @typedef {import("./api.js").Scan} Scan */
/** @typedef {import("./api.js").Finding} Finding */
/** @typedef {import("./api.js").Drift} Drift */
/** @typedef {import("./api.js").History} History */
/** @typedef {"verified" | "warn" | "fail" | "unknown"} LinkState */

/**
 * @typedef {Object} ChainLink
 * @property {string} step
 * @property {LinkState} state
 * @property {string} verdict
 * @property {string} evidence
 */

/**
 * @typedef {Object} AttentionItem
 * @property {"fail" | "warn"} level
 * @property {string} title
 * @property {string} detail
 * @property {string} href
 */

/**
 * The newest scan for each project and branch. Scans arrive oldest first.
 * @param {Scan[]} scans
 * @returns {Scan[]}
 */
export function latestScans(scans) {
  const latest = new Map();
  for (const scan of scans) latest.set(`${scan.project || scan.id}\n${scan.branch || ""}\n${scan.pullRequest || ""}`, scan);
  return [...latest.values()].reverse();
}

/**
 * @param {Finding[]} findings
 */
export function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, none: 0, kev: 0, total: findings.length };
  for (const finding of findings) {
    counts[severity(finding.score)] += 1;
    if (finding.kev) counts.kev += 1;
  }
  return counts;
}

/**
 * @param {History} history
 * @param {string} scanId
 * @returns {Drift | undefined}
 */
export function driftInto(history, scanId) {
  return history.drifts.find((drift) => drift.after === scanId);
}

/**
 * The evidence behind one scan, as four links. Each link states only what the
 * report records.
 * @param {Scan} scan
 * @param {Date} now
 * @returns {ChainLink[]}
 */
export function evidenceChain(scan, now) {
  const fresh = freshness(scan.snapshot, now);
  /** @type {ChainLink} */
  const snapshot = {
    step: "Vulnerability data",
    state: fresh.freshness === "current" ? "verified" : fresh.freshness === "aging" ? "warn" : fresh.freshness === "stale" ? "fail" : "unknown",
    verdict: { current: "Current", aging: "Aging", stale: "Stale", unknown: "Time not recorded" }[fresh.freshness],
    evidence: fresh.age === null ? "The report has no snapshot time." : `Snapshot ${fresh.age === 0 ? "from today" : `${plural(fresh.age, "day")} old`}`,
  };
  /** @type {ChainLink} */
  let signature;
  if (scan.authenticity === "signed") {
    signature = { step: "Signature", state: "verified", verdict: "Verified", evidence: `Key ${scan.signatureKey || "not named"}` };
  } else if (scan.authenticity === "unsigned") {
    signature = { step: "Signature", state: "fail", verdict: "Not verified", evidence: "The scan used an unsigned snapshot." };
  } else {
    signature = { step: "Signature", state: "unknown", verdict: "Not recorded", evidence: "This report predates signature recording." };
  }
  /** @type {ChainLink} */
  const checksum = scan.checksum
    ? { step: "Checksum", state: "verified", verdict: "Matched", evidence: `Snapshot zip matched its manifest digest.` }
    : { step: "Checksum", state: "unknown", verdict: "Not recorded", evidence: "The report has no snapshot digest." };
  /** @type {ChainLink} */
  const engine = scan.engine
    ? { step: "Engine", state: "verified", verdict: `Dependency-Check ${scan.engine}`, evidence: "The engine release this scan ran with." }
    : { step: "Engine", state: "unknown", verdict: "Not recorded", evidence: "The report has no engine version." };
  return [snapshot, signature, checksum, engine];
}

/**
 * What needs a person, most severe first, from the newest scans.
 * @param {History} history
 * @param {Date} now
 * @returns {AttentionItem[]}
 */
export function attention(history, now) {
  /** @type {AttentionItem[]} */
  const items = [];
  for (const scan of latestScans(history.scans)) {
    const name = scanName(scan);
    const href = `#/scans/${encodeURIComponent(scan.id)}`;
    const counts = severityCounts(scan.findings || []);
    if (counts.kev) {
      items.push({ level: "fail", title: `${name}: ${plural(counts.kev, "finding")} actively exploited`, detail: "On the CISA Known Exploited Vulnerabilities list. Fix these first.", href });
    }
    if (counts.critical) {
      items.push({ level: "fail", title: `${name}: ${plural(counts.critical, "critical finding")}`, detail: "CVSS 9.0 or higher in the latest scan.", href });
    }
    const drift = driftInto(history, scan.id);
    const added = drift ? drift.findings.added.length : 0;
    if (added) {
      items.push({ level: "warn", title: `${name}: ${plural(added, "new finding")} since the previous scan`, detail: "Introduced between the last two scans on this branch.", href: `${href}/changes` });
    }
    const fresh = freshness(scan.snapshot, now);
    if (fresh.freshness === "stale") {
      items.push({ level: "warn", title: `${name}: scanned with ${plural(fresh.age || 0, "day")}-old data`, detail: "Vulnerabilities published since then are missing. Scan again with a current snapshot.", href: `${href}/evidence` });
    }
    if (scan.authenticity === "unsigned") {
      items.push({ level: "warn", title: `${name}: snapshot signature not verified`, detail: "The scan accepted an unsigned snapshot. Pin a snapshot key or set CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1.", href: `${href}/evidence` });
    }
  }
  return items.sort((a, b) => (a.level === b.level ? 0 : a.level === "fail" ? -1 : 1));
}

/**
 * Scans grouped by branch, newest first in each group.
 * @param {Scan[]} scans
 * @returns {{branch: string, scans: Scan[]}[]}
 */
export function branchGroups(scans) {
  /** @type {Map<string, Scan[]>} */
  const groups = new Map();
  for (const scan of [...scans].reverse()) {
    const key = scan.branch || "";
    if (!groups.has(key)) groups.set(key, []);
    /** @type {Scan[]} */ (groups.get(key)).push(scan);
  }
  return [...groups.entries()].map(([branch, items]) => ({ branch, scans: items }));
}

/**
 * Stable key for one finding row.
 * @param {Finding} finding
 */
export function findingKey(finding) {
  return [finding.id, finding.package || finding.dependency, finding.relationship || "", finding.scope || ""].join("\n");
}

/**
 * @param {Finding} finding
 */
export function packageLabel(finding) {
  return finding.package || finding.dependency || "—";
}
