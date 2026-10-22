// @ts-check
// Hash routes, so every view has a link that survives a reload and the
// server needs no route of its own.

/**
 * @typedef {Object} Route
 * @property {"overview" | "repositories" | "scans" | "scan" | "evidence" | "builds" | "access" | "not-found"} name
 * @property {Record<string, string>} params
 */

/** @type {[RegExp, Route["name"], string[]][]} */
const TABLE = [
  [/^\/?$/, "overview", []],
  [/^\/overview$/, "overview", []],
  [/^\/repositories$/, "repositories", []],
  [/^\/scans$/, "scans", []],
  [/^\/scans\/([^/]+)$/, "scan", ["id"]],
  [/^\/scans\/([^/]+)\/(findings|changes|dependencies|evidence)$/, "scan", ["id", "tab"]],
  [/^\/evidence$/, "evidence", []],
  [/^\/builds$/, "builds", []],
  [/^\/access$/, "access", []],
];

/**
 * @param {string} hash  location.hash, with or without the leading "#"
 * @returns {Route}
 */
export function parseRoute(hash) {
  const path = (hash || "").replace(/^#/, "").split("?")[0];
  for (const [pattern, name, keys] of TABLE) {
    const match = pattern.exec(path);
    if (!match) continue;
    /** @type {Record<string, string>} */
    const params = {};
    keys.forEach((key, index) => {
      const raw = match[index + 1];
      if (raw !== undefined) {
        try {
          params[key] = decodeURIComponent(raw);
        } catch {
          params[key] = raw;
        }
      }
    });
    return { name, params };
  }
  return { name: "not-found", params: { path } };
}

/**
 * @param {Route["name"]} name
 * @param {Record<string, string>} [params]
 */
export function href(name, params = {}) {
  if (name === "scan") {
    const base = `#/scans/${encodeURIComponent(params.id || "")}`;
    return params.tab && params.tab !== "findings" ? `${base}/${params.tab}` : base;
  }
  return name === "overview" ? "#/" : `#/${name}`;
}
