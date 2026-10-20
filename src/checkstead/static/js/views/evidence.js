// @ts-check
// Evidence: which vulnerability-data snapshots the newest scans used, and how
// far each can be trusted.

import { dataTable, stateBlock, timeEl } from "../components.js";
import { h } from "../dom.js";
import { plural, scanName, shortDigest, utcLabel } from "../format.js";
import { latestScans } from "../model.js";
import { href } from "../router.js";
import { pageHead, withLoad } from "./common.js";
import { dataTag, signatureTag } from "./overview.js";

/** @typedef {import("../app.js").Context} Context */
/** @typedef {import("../api.js").History} History */
/** @typedef {import("../api.js").Scan} Scan */

/** @param {Context} ctx */
export function renderEvidence(ctx) {
  return h(
    "div",
    null,
    pageHead("Evidence", "The vulnerability data behind the newest scans: when it was published, whether its digest matched, and whether its signature was verified."),
    withLoad(ctx, "history", (/** @type {History} */ history) => evidence(ctx, history)),
  );
}

/**
 * @param {Context} ctx
 * @param {History} history
 */
function evidence(ctx, history) {
  const latest = latestScans(history.scans);
  if (!latest.length) {
    return stateBlock({ iconName: "evidence", title: "No evidence yet", body: "Each scan records the snapshot it used. Run a scan to see it here." });
  }
  /** @type {Map<string, {snapshot: string, checksum: string, scans: Scan[]}>} */
  const snapshots = new Map();
  for (const scan of latest) {
    const key = `${scan.snapshot}\n${scan.checksum}`;
    if (!snapshots.has(key)) snapshots.set(key, { snapshot: scan.snapshot, checksum: scan.checksum, scans: [] });
    /** @type {{scans: Scan[]}} */ (snapshots.get(key)).scans.push(scan);
  }
  const rows = [...snapshots.values()].sort((a, b) => b.snapshot.localeCompare(a.snapshot));
  return h(
    "div",
    null,
    h(
      "section",
      { class: "section", "aria-labelledby": "snapshots-head" },
      h("h2", { id: "snapshots-head" }, `${plural(rows.length, "snapshot")} in use`),
      dataTable({
        caption: "Snapshots used by the newest scans",
        columns: [
          { key: "time", label: "Published", cell: (row) => h("span", { title: utcLabel(row.snapshot) }, utcLabel(row.snapshot), h("br"), h("span", { class: "muted small" }, timeEl(row.snapshot, ctx.now))) },
          { key: "data", label: "Freshness", cell: (row) => dataTag(row.scans[0], ctx.now) },
          { key: "digest", label: "Zip digest", cell: (row) => h("span", { class: "id", title: row.checksum }, shortDigest(row.checksum, 16)) },
          { key: "sig", label: "Signature", cell: (row) => signatureTag(row.scans[0]) },
          { key: "scans", label: "Used by", cell: (row) => h("span", null, row.scans.flatMap((scan, index) => [index ? ", " : null, h("a", { href: href("scan", { id: scan.id, tab: "evidence" }) }, scanName(scan))])) },
        ],
        groups: [{ label: null, rows }],
      }),
    ),
    h(
      "section",
      { class: "section panel", "aria-labelledby": "how-head" },
      h("h2", { id: "how-head" }, "How a scan earns trust"),
      h(
        "ol",
        null,
        h("li", null, "The daily updater builds the vulnerability database from the NVD, checks it finds a known CVE, and signs the manifest."),
        h("li", null, "The scan client downloads the manifest and the zip, and refuses a zip whose SHA-256 does not match."),
        h("li", null, "With a pinned key, it refuses a missing or invalid signature, and an older snapshot than one it already used."),
        h("li", null, "Dependency-Check runs offline against that data with the pinned engine release, and the report records all of the above."),
      ),
      h("p", { class: "muted small" }, "Older reports did not record the signature result. They show “Not recorded” rather than a guess."),
    ),
  );
}
