// @ts-check
// Application state, data loading, and the shell. Views are pure functions of
// the state below; every load has an explicit loading, error, and ready state.

import { ApiError } from "./api.js";
import { avatar, banner, errorState, skeleton } from "./components.js";
import { h, icon } from "./dom.js";
import { providerName } from "./format.js";
import { href, parseRoute } from "./router.js";
import { forgetUploadToken, renderAccess } from "./views/access.js";
import { renderBuilds } from "./views/builds.js";
import { renderEvidence } from "./views/evidence.js";
import { renderNotFound } from "./views/not-found.js";
import { renderOverview } from "./views/overview.js";
import { renderRepositories } from "./views/repositories.js";
import { renderScan, renderScans } from "./views/scans.js";
import { renderSignIn } from "./views/signin.js";

/** @typedef {import("./api.js").Client} Client */
/** @typedef {import("./api.js").User} User */
/** @typedef {import("./router.js").Route} Route */

/**
 * @template T
 * @typedef {{status: "idle" | "loading" | "ready" | "error", data: T | null, error: ApiError | Error | null}} Load
 */

/** @typedef {"history" | "builds" | "users" | "repositories" | "runs" | "uploadTokens"} LoadKey */

/**
 * @typedef {Object} State
 * @property {"loading" | "signed-out" | "signed-in" | "error"} session
 * @property {User | null} user
 * @property {Error | null} sessionError
 * @property {Load<import("./api.js").History>} history
 * @property {Load<import("./api.js").BuildRuns>} builds
 * @property {Load<{users: User[]}>} users
 * @property {Load<import("./api.js").Repositories>} repositories
 * @property {Load<import("./api.js").SourceRuns>} runs
 * @property {Load<{uploadTokens: import("./api.js").UploadToken[]}>} uploadTokens
 * @property {Map<string, Load<import("./api.js").ScanDetail>>} scans  Full scans by id, loaded when opened
 * @property {boolean} online
 * @property {{relationship: string, scope: string, query: string, kevOnly: boolean, sort: string, descending: boolean, selected: string | null}} findings
 * @property {{query: string}} dependencies
 * @property {string | null} toast
 */

/**
 * @typedef {Object} Context
 * @property {State} state
 * @property {Route} route
 * @property {Date} now
 * @property {Client} api
 * @property {() => void} render
 * @property {(key: LoadKey, force?: boolean) => void} load
 * @property {(id: string) => Load<import("./api.js").ScanDetail>} scanDetail
 * @property {(message: string) => void} notify
 * @property {() => Promise<void>} signedIn
 */

const NAV = /** @type {const} */ ([
  ["overview", "Overview", "overview"],
  ["repositories", "Repositories", "repos"],
  ["scans", "Scans", "scans"],
  ["evidence", "Evidence", "evidence"],
  ["builds", "CI runs", "builds"],
  ["access", "Access", "people"],
]);

/** @returns {Load<any>} */
function idle() {
  return { status: "idle", data: null, error: null };
}

/**
 * @param {{root: HTMLElement, api: Client, now?: () => Date, storage?: Storage | null}} options
 */
export function createApp({ root, api, now = () => new Date(), storage = safeStorage() }) {
  /** @type {State} */
  const state = {
    session: "loading",
    user: null,
    sessionError: null,
    history: idle(),
    builds: idle(),
    users: idle(),
    repositories: idle(),
    runs: idle(),
    uploadTokens: idle(),
    scans: new Map(),
    online: typeof navigator === "undefined" ? true : navigator.onLine !== false,
    findings: { relationship: "", scope: "", query: "", kevOnly: false, sort: "score", descending: true, selected: null },
    dependencies: { query: "" },
    toast: null,
  };
  let lastRoute = "";
  /** @type {ReturnType<typeof setTimeout> | null} */
  let toastTimer = null;

  /** @type {Record<LoadKey, () => Promise<any>>} */
  const loaders = {
    history: () => api.history(),
    builds: () => api.builds(),
    users: () => api.users(),
    repositories: () => api.repositories(),
    runs: () => api.runs(),
    uploadTokens: () => api.uploadTokens(),
  };

  /**
   * @param {LoadKey} key
   * @param {boolean} [force]
   */
  function load(key, force = false) {
    // The three slots share one shape; the loader decides the data type.
    const slots = /** @type {Record<string, Load<any>>} */ (/** @type {unknown} */ (state));
    const slot = slots[key];
    if (!force && (slot.status === "loading" || slot.status === "ready")) return;
    slots[key] = { status: "loading", data: slot.data, error: null };
    render();
    loaders[key]().then(
      (data) => {
        slots[key] = { status: "ready", data, error: null };
        if (key === "history") state.scans.clear();
        render();
      },
      (error) => {
        if (error instanceof ApiError && error.kind === "auth") {
          state.session = "signed-out";
          state.user = null;
        }
        slots[key] = { status: "error", data: slot.data, error };
        render();
      },
    );
  }

  /**
   * The full scan, loading it the first time it is asked for.
   * @param {string} id
   * @returns {Load<import("./api.js").ScanDetail>}
   */
  function scanDetail(id) {
    const known = state.scans.get(id);
    if (known) return known;
    /** @type {Load<import("./api.js").ScanDetail>} */
    const loading = { status: "loading", data: null, error: null };
    state.scans.set(id, loading);
    api.scan(id).then(
      (data) => {
        state.scans.set(id, { status: "ready", data, error: null });
        render();
      },
      (error) => {
        state.scans.set(id, { status: "error", data: null, error });
        render();
      },
    );
    return loading;
  }

  /** @param {string} message */
  function notify(message) {
    state.toast = message;
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      state.toast = null;
      render();
    }, 4000);
    render();
  }

  async function checkSession() {
    try {
      const { user } = await api.session();
      state.user = user;
      state.session = "signed-in";
    } catch (error) {
      if (error instanceof ApiError && error.kind === "auth") {
        state.session = "signed-out";
      } else {
        state.session = "error";
        state.sessionError = /** @type {Error} */ (error);
      }
    }
    render();
  }

  async function signedIn() {
    state.history = idle();
    state.builds = idle();
    state.users = idle();
    state.repositories = idle();
    state.runs = idle();
    state.uploadTokens = idle();
    state.scans.clear();
    await checkSession();
  }

  async function signOut() {
    try {
      await api.signOut();
    } finally {
      state.session = "signed-out";
      state.user = null;
      state.history = idle();
      state.builds = idle();
      state.users = idle();
      state.repositories = idle();
      state.runs = idle();
      state.uploadTokens = idle();
      window.location.hash = "#/";
      render();
    }
  }

  function render() {
    const route = parseRoute(window.location.hash);
    /** @type {Context} */
    const ctx = { state, route, now: now(), api, render, load, scanDetail, notify, signedIn };
    if (state.session === "loading") {
      root.replaceChildren(h("main", { class: "gate", id: "main" }, skeleton(3)));
      return;
    }
    if (state.session === "error") {
      root.replaceChildren(h("main", { class: "gate", id: "main" }, h("div", { class: "gate-card" }, errorState(state.sessionError || new Error("Unknown error"), () => void checkSession()))));
      return;
    }
    if (state.session === "signed-out") {
      root.replaceChildren(renderSignIn(ctx));
      return;
    }
    const active = document.activeElement;
    const fromTab = active instanceof HTMLElement && active.getAttribute("role") === "tab" && root.contains(active);
    const content = view(ctx);
    root.replaceChildren(shell(ctx, content));
    const key = route.name + JSON.stringify(route.params);
    if (key !== lastRoute) {
      // Arrowing between tabs keeps focus on the tabs; any other new page
      // moves focus to its heading so screen readers announce it.
      const tab = fromTab ? root.querySelector('[role="tab"][aria-selected="true"]') : null;
      const heading = root.querySelector("main h1");
      if (tab instanceof HTMLElement) {
        tab.focus();
      } else if (heading instanceof HTMLElement && lastRoute) {
        heading.setAttribute("tabindex", "-1");
        heading.focus({ preventScroll: false });
      }
      lastRoute = key;
    }
  }

  /** @param {Context} ctx */
  function view(ctx) {
    if (ctx.route.name !== "access") forgetUploadToken();
    switch (ctx.route.name) {
      case "overview": return renderOverview(ctx);
      case "repositories": return renderRepositories(ctx);
      case "scans": return renderScans(ctx);
      case "scan": return renderScan(ctx);
      case "evidence": return renderEvidence(ctx);
      case "builds": return renderBuilds(ctx);
      case "access": return renderAccess(ctx);
      default: return renderNotFound(ctx);
    }
  }

  /**
   * @param {Context} ctx
   * @param {Node} content
   */
  function shell(ctx, content) {
    const current = ctx.route.name === "scan" ? "scans" : ctx.route.name;
    const user = state.user;
    const items = NAV.filter(([name]) => name !== "access" || (user && user.role === "admin"));
    const rail = h(
      "nav",
      { class: "rail", "aria-label": "Primary" },
      h("a", { class: "brand", href: "#/" }, icon("shield"), "Checkstead"),
      h(
        "div",
        { class: "nav" },
        items.map(([name, label, iconName]) => h("a", { href: href(name), "aria-current": current === name ? "page" : null }, icon(iconName), label)),
      ),
      h(
        "div",
        { class: "rail-foot" },
        user
          ? h(
              "div",
              { class: "who" },
              avatar(user),
              h(
                "span",
                null,
                h("strong", null, user.provider === "local" ? "Signed in on this computer" : user.displayName || user.login),
                h("span", null, user.provider === "local" ? (user.role === "admin" ? "Administrator" : "Member") : `${user.role === "admin" ? "Administrator" : "Member"}, ${providerName(user.provider)}`),
              ),
            )
          : null,
        themeSwitch(),
        h("button", { type: "button", class: "btn", onclick: () => void signOut() }, icon("out"), "Sign out"),
      ),
    );
    const notices = [];
    if (!state.online) notices.push(banner("warn", "You are offline.", " What you see was loaded earlier and will not update until the connection returns."));
    // The NVD terms of use require this notice wherever its data is shown.
    const notice = state.history.data && state.history.data.notice;
    const main = h("main", { class: "main", id: "main" }, notices, content, notice ? h("footer", { class: "attribution" }, notice) : null);
    return h("div", { class: "shell" }, rail, main, state.toast ? h("div", { class: "toast", role: "status" }, state.toast) : null);
  }

  function themeSwitch() {
    const current = readTheme();
    /** @param {string} value */
    const pick = (value) => {
      try {
        if (value === "system") storage?.removeItem("checkstead-theme");
        else storage?.setItem("checkstead-theme", value);
      } catch {
        // Storage can be blocked; the choice then lasts for this page only.
      }
      applyTheme(value);
      render();
    };
    return h(
      "div",
      { class: "theme", role: "group", "aria-label": "Colour theme" },
      [["system", "Auto"], ["light", "Light"], ["dark", "Dark"]].map(([value, label]) =>
        h("button", { type: "button", "aria-pressed": current === value ? "true" : "false", onclick: () => pick(value) }, label),
      ),
    );
  }

  function readTheme() {
    try {
      return storage?.getItem("checkstead-theme") || "system";
    } catch {
      return "system";
    }
  }

  function start() {
    applyTheme(readTheme());
    window.addEventListener("hashchange", render);
    window.addEventListener("online", () => {
      state.online = true;
      render();
    });
    window.addEventListener("offline", () => {
      state.online = false;
      render();
    });
    render();
    return checkSession();
  }

  return { start, state, render };
}

/** @param {string} value */
function applyTheme(value) {
  if (value === "light" || value === "dark") document.documentElement.setAttribute("data-theme", value);
  else document.documentElement.removeAttribute("data-theme");
}

function safeStorage() {
  try {
    return typeof window !== "undefined" ? window.localStorage : null;
  } catch {
    return null;
  }
}
