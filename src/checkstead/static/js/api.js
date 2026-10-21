// @ts-check
// The server's JSON contracts and a client for them. These types describe
// what src/checkstead/ui.py and history.py return; nothing here invents data.

/**
 * @typedef {Object} Finding
 * @property {string} id                 CVE, GHSA, or other identifier
 * @property {string} dependency
 * @property {Record<string, string>} cvss
 * @property {string=} score             The score the policy judged on, as text
 * @property {string=} scoreSource       NVD, NPM, OSSINDEX, ...
 * @property {string=} relationship      "direct" | "transitive"
 * @property {string=} scope             "production" | "dev"
 * @property {string=} description
 * @property {string=} package
 * @property {boolean=} kev              On the CISA KEV list. Absent when not recorded.
 */

/**
 * @typedef {Object} Dependency
 * @property {string} name
 * @property {string} version
 * @property {string} fileName
 * @property {string} sha256
 */

/**
 * @typedef {Object} ScanPolicy
 * @property {string=} scorePolicy
 * @property {string=} threshold
 * @property {string=} failOnKev
 * @property {string=} failUnscored
 */

/**
 * @typedef {Object} Scan
 * @property {string} id
 * @property {string|null} project
 * @property {string} engine
 * @property {string} snapshot           UTC time, 2026-10-20T05:32:17Z
 * @property {string} checksum           sha256:<hex>
 * @property {string|null} revision
 * @property {string|null} author
 * @property {string|null} authorEmail
 * @property {boolean} hasDependencyReport
 * @property {boolean} hasScoreSource
 * @property {string[]} scoreLines
 * @property {string|null} pullRequest
 * @property {string|null} branch
 * @property {string|null=} authenticity "signed" | "unsigned" | null when the report predates the field
 * @property {string|null=} signatureKey
 * @property {ScanPolicy=} policy
 * @property {Dependency[]=} dependencies  Present in /api/scans/<id> and /api/history
 * @property {number=} dependencyCount     Present in /api/history/summary
 * @property {Finding[]} findings
 */

/**
 * @typedef {Object} Drift
 * @property {string} before
 * @property {string} after
 * @property {{added: Dependency[], removed: Dependency[], changed: {before: Dependency, after: Dependency}[]}=} dependencies  Full payloads only
 * @property {{added: number, removed: number, changed: number}=} dependencyCounts  Summary only
 * @property {{added: Finding[], removed: Finding[], changed: {before: Finding, after: Finding}[]}} findings
 * @property {{available: boolean}} scores
 */

/**
 * @typedef {Object} History
 * @property {string} notice
 * @property {Scan[]} scans
 * @property {Drift[]} drifts
 */

/**
 * @typedef {Object} ScanDetail
 * @property {string} notice
 * @property {Scan} scan
 * @property {Drift | null} drift
 */

/**
 * @typedef {Object} User
 * @property {number} id
 * @property {string} provider
 * @property {string} login
 * @property {string} displayName
 * @property {"admin"|"user"} role
 */

/**
 * @typedef {Object} Provider
 * @property {string} key
 * @property {string} label
 * @property {boolean=} organization  The provider needs an organization name
 * @property {boolean=} sso
 */

/**
 * Azure DevOps is on once an administrator has added an Azure DevOps login.
 * @typedef {{
 *   github: {enabled: boolean, start: string},
 *   entra: {enabled: boolean, start: string, tenant: string},
 *   local: {enabled: boolean},
 *   "azure-devops"?: {enabled: boolean},
 * }} SsoStatus
 */

/**
 * @typedef {Object} BuildRun
 * @property {string|number} id
 * @property {string=} repository
 * @property {string=} name
 * @property {string=} status
 * @property {string=} url
 * @property {string=} branch
 * @property {string|number=} pullRequest
 * @property {string|null=} pullRequestUrl
 * @property {string=} updatedAt
 */

/**
 * @typedef {Object} BuildRuns
 * @property {boolean} connected
 * @property {BuildRun[]} runs
 * @property {string=} notice
 * @property {string=} approvalUrl
 */

/** @typedef {"auth" | "forbidden" | "offline" | "timeout" | "server" | "invalid" | "not-found" | "conflict"} ErrorKind */

export class ApiError extends Error {
  /**
   * @param {ErrorKind} kind
   * @param {string} message
   * @param {number} [status]
   */
  constructor(kind, message, status = 0) {
    super(message);
    this.kind = kind;
    this.status = status;
  }
}

/**
 * @param {number} status
 * @returns {ErrorKind}
 */
export function kindForStatus(status) {
  if (status === 401) return "auth";
  if (status === 403) return "forbidden";
  if (status === 404) return "not-found";
  if (status === 409) return "conflict";
  if (status >= 500 || status === 503) return "server";
  return "invalid";
}

const TIMEOUT_MS = 20000;

/**
 * @template T
 * @param {string} path
 * @param {RequestInit} [options]
 * @param {typeof fetch} [fetcher]
 * @returns {Promise<T>}
 */
export async function request(path, options = {}, fetcher = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response;
  try {
    response = await fetcher(path, {
      credentials: "same-origin",
      ...options,
      headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.headers || {}) },
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new ApiError("timeout", "The server did not answer within 20 seconds.");
    }
    throw new ApiError("offline", "The server could not be reached. Check the connection and try again.");
  } finally {
    clearTimeout(timer);
  }
  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }
  if (!response.ok) {
    const message = payload && typeof payload.error === "string" ? payload.error : `The server answered HTTP ${response.status}.`;
    throw new ApiError(kindForStatus(response.status), message, response.status);
  }
  return /** @type {T} */ (payload);
}

/** @param {typeof fetch} [fetcher] */
export function client(fetcher = fetch) {
  /**
   * @template T
   * @param {string} path
   * @param {RequestInit} [options]
   * @returns {Promise<T>}
   */
  const call = (path, options) => request(path, options, fetcher);
  return {
    /** @returns {Promise<{user: User}>} */
    session: () => call("/api/session"),
    /** @returns {Promise<{user: User}>} */
    signInLocal: () => call("/api/session/local", { method: "POST", body: "{}" }),
    /** Access token sign-in (Azure DevOps PAT). The token is checked once and not kept. @param {{provider: string, organization: string, token: string}} body @returns {Promise<{user: User}>} */
    signInWithToken: (body) => call("/api/session", { method: "POST", body: JSON.stringify(body) }),
    /** @returns {Promise<{signedOut: boolean}>} */
    signOut: () => call("/api/session", { method: "DELETE" }),
    /** @returns {Promise<SsoStatus>} */
    sso: () => call("/api/sso"),
    /** @returns {Promise<{providers: Provider[], later: string}>} */
    providers: () => call("/api/providers"),
    /** Scans and findings without dependency lists. @returns {Promise<History>} */
    history: () => call("/api/history/summary"),
    /** One scan in full. @param {string} id @returns {Promise<ScanDetail>} */
    scan: (id) => call(`/api/scans/${encodeURIComponent(id)}`),
    /** @returns {Promise<{users: User[]}>} */
    users: () => call("/api/admin/users"),
    /** @param {{provider: string, login: string, role: string}} body @returns {Promise<{user: User}>} */
    addUser: (body) => call("/api/admin/users", { method: "POST", body: JSON.stringify(body) }),
    /** @param {number} id @param {string} role @returns {Promise<{user: User}>} */
    setRole: (id, role) => call(`/api/admin/users/${encodeURIComponent(String(id))}`, { method: "PATCH", body: JSON.stringify({ role }) }),
    /** @param {number} id @returns {Promise<{removed: number}>} */
    removeUser: (id) => call(`/api/admin/users/${encodeURIComponent(String(id))}`, { method: "DELETE" }),
    /** @returns {Promise<BuildRuns>} */
    builds: () => call("/api/github/runs"),
    /** @param {string} repository @param {string|number} run @returns {Promise<unknown>} */
    rerun: (repository, run) => call("/api/github/rerun", { method: "POST", body: JSON.stringify({ repository, run }) }),
  };
}

/** @typedef {ReturnType<typeof client>} Client */
