// @ts-check
// Formatting and the freshness rules. Freshness matches the scan client
// (src/checkstead/snapshot.py): current up to 1 day, aging up to 7, stale after.

export const MAX_SNAPSHOT_AGE_DAYS = 7;
const DAY_MS = 86400000;

/**
 * @param {string | null | undefined} value
 * @returns {Date | null}
 */
export function parseUtc(value) {
  if (!value || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Whole UTC days between a snapshot time and now, counted by calendar day
 * like the scan client does.
 * @param {string} snapshot
 * @param {Date} now
 * @returns {number | null}
 */
export function ageDays(snapshot, now) {
  const date = parseUtc(snapshot);
  if (!date) return null;
  const start = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((today - start) / DAY_MS);
}

/** @typedef {"current" | "aging" | "stale" | "unknown"} Freshness */

/**
 * @param {string} snapshot
 * @param {Date} now
 * @returns {{freshness: Freshness, age: number | null}}
 */
export function freshness(snapshot, now) {
  const age = ageDays(snapshot, now);
  if (age === null) return { freshness: "unknown", age: null };
  if (age > MAX_SNAPSHOT_AGE_DAYS) return { freshness: "stale", age };
  if (age > 1) return { freshness: "aging", age };
  return { freshness: "current", age };
}

/**
 * "3 hours ago", "in 2 days". Exact UTC time goes in a title or a <time>.
 * @param {string} value
 * @param {Date} now
 * @returns {string}
 */
export function relativeTime(value, now) {
  const date = parseUtc(value) || (value ? new Date(value) : null);
  if (!date || Number.isNaN(date.getTime())) return "time not recorded";
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const units = /** @type {const} */ ([["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]]);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return formatter.format(Math.trunc(seconds / size), unit);
  }
  return "just now";
}

/**
 * @param {string} value
 * @returns {string} "20 Oct 2026, 05:32 UTC"
 */
export function utcLabel(value) {
  const date = parseUtc(value);
  if (!date) return value || "not recorded";
  const day = date.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
  const time = date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
  return `${day}, ${time} UTC`;
}

/** @typedef {"critical" | "high" | "medium" | "low" | "none"} Severity */

/**
 * CVSS bands. A finding without a score is "none", never "low".
 * @param {string | number | null | undefined} score
 * @returns {Severity}
 */
export function severity(score) {
  const value = Number(score);
  if (score === null || score === undefined || score === "" || !Number.isFinite(value)) return "none";
  if (value >= 9) return "critical";
  if (value >= 7) return "high";
  if (value >= 4) return "medium";
  return "low";
}

/** @param {Severity} band */
export function severityLabel(band) {
  return { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "No score" }[band];
}

/**
 * @param {string | null | undefined} checksum
 * @param {number} [keep]
 */
export function shortDigest(checksum, keep = 12) {
  if (!checksum) return "not recorded";
  const hex = checksum.replace(/^sha256:/, "");
  return hex.length > keep ? `${hex.slice(0, keep)}…` : hex;
}

/** @param {{project: string | null, id: string, pullRequest: string | null}} scan */
export function scanName(scan) {
  const name = scan.project || scan.id;
  return scan.pullRequest ? `${name} #${scan.pullRequest}` : name;
}

/**
 * @param {number} count
 * @param {string} one
 * @param {string} [many]
 */
export function plural(count, one, many) {
  return `${count} ${count === 1 ? one : many || `${one}s`}`;
}

/** @param {string} key */
export function providerName(key) {
  return { github: "GitHub", "azure-devops": "Azure DevOps", entra: "Microsoft Entra", local: "This computer" }[key] || key;
}
