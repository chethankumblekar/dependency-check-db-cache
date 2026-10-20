// @ts-check
// Reusable pieces. Each takes plain data and returns a node; none fetch.

import { h, icon } from "./dom.js";
import { relativeTime, severity, severityLabel, utcLabel } from "./format.js";

/** @typedef {import("./model.js").ChainLink} ChainLink */
/** @typedef {import("./model.js").AttentionItem} AttentionItem */
/** @typedef {import("./api.js").ApiError} ApiError */

/**
 * Severity mark: colour plus text, never colour alone.
 * @param {string | undefined} score
 */
export function severityMark(score) {
  const band = severity(score);
  const label = band === "none" ? "No score" : `${severityLabel(band)} ${score}`;
  return h("span", { class: `sev sev-${band}` }, label);
}

export function kevTag() {
  return h("span", { class: "tag kev", title: "On the CISA Known Exploited Vulnerabilities list" }, "Exploited");
}

/**
 * Relative time with the exact UTC time a hover or screen reader away.
 * @param {string} value
 * @param {Date} now
 */
export function timeEl(value, now) {
  return h("time", { datetime: value, title: utcLabel(value) }, relativeTime(value, now));
}

/** @param {"verified" | "warn" | "fail" | "unknown"} state */
function stateIcon(state) {
  return icon(state === "verified" ? "check" : state === "fail" ? "cross" : state === "warn" ? "alert" : "dot");
}

/**
 * @param {ChainLink[]} links
 * @param {string} label
 */
export function evidenceChain(links, label) {
  return h(
    "ol",
    { class: "chain", "aria-label": label },
    links.map((link) =>
      h(
        "li",
        { class: `link state-${link.state}` },
        h("span", { class: "step" }, link.step),
        h("span", { class: "verdict" }, stateIcon(link.state), link.verdict),
        h("span", { class: "evidence" }, link.evidence),
      ),
    ),
  );
}

/**
 * @param {AttentionItem[]} items
 */
export function attentionList(items) {
  return h(
    "ul",
    { class: "attention", "aria-label": "Needs attention" },
    items.map((item) =>
      h(
        "li",
        { class: item.level === "fail" ? "state-fail" : "state-warn" },
        icon(item.level === "fail" ? "cross" : "alert"),
        h("div", null, h("strong", null, item.title), h("p", null, item.detail)),
        h("a", { href: item.href, class: "small" }, "Open"),
      ),
    ),
  );
}

/**
 * @param {{title: string, body: string, action?: Node | null, iconName?: import("./dom.js").IconName}} options
 */
export function stateBlock({ title, body, action, iconName }) {
  return h("section", { class: "state", role: "status" }, iconName ? icon(iconName) : null, h("h2", null, title), h("p", null, body), action || null);
}

/**
 * The state for a failed load, by what went wrong, with a way out.
 * @param {ApiError | Error} error
 * @param {() => void} retry
 */
export function errorState(error, retry) {
  const kind = /** @type {any} */ (error).kind;
  const again = h("button", { type: "button", class: "btn", onclick: () => retry() }, "Try again");
  if (kind === "forbidden") {
    return stateBlock({ iconName: "lock", title: "You do not have access to this", body: "An administrator can change your role under Access.", action: h("a", { class: "btn", href: "#/" }, "Go to overview") });
  }
  if (kind === "offline") {
    return stateBlock({ iconName: "offline", title: "The server cannot be reached", body: error.message, action: again });
  }
  if (kind === "timeout") {
    return stateBlock({ iconName: "clock", title: "The server is taking too long", body: error.message, action: again });
  }
  return stateBlock({ iconName: "alert", title: "This could not be loaded", body: error.message, action: again });
}

/** @param {number} [lines] */
export function skeleton(lines = 3) {
  return h("div", { class: "skeleton", role: "status", "aria-label": "Loading" }, Array.from({ length: lines }, () => h("span")));
}

/**
 * @param {"warn" | "fail" | "info"} level
 * @param {string} title
 * @param {string} body
 */
export function banner(level, title, body) {
  return h("div", { class: `banner ${level}`, role: level === "info" ? "status" : "alert" }, icon(level === "info" ? "dot" : "alert"), h("p", null, h("strong", null, title), body));
}

/**
 * @param {string} label
 * @param {[string, string][]} options value, text
 * @param {string} current
 * @param {(value: string) => void} onPick
 */
export function segmented(label, options, current, onPick) {
  return h(
    "div",
    { class: "segmented", role: "group", "aria-label": label },
    options.map(([value, text]) => h("button", { type: "button", "aria-pressed": value === current ? "true" : "false", onclick: () => onPick(value) }, text)),
  );
}

/**
 * Tabs that are links, so each tab has a URL.
 * @param {string} label
 * @param {{id: string, text: string, href: string}[]} tabs
 * @param {string} current
 */
export function tabs(label, tabs, current) {
  return h(
    "div",
    { class: "tabs", role: "tablist", "aria-label": label },
    tabs.map((tab) =>
      h("button", {
        type: "button",
        role: "tab",
        id: `tab-${tab.id}`,
        "aria-selected": tab.id === current ? "true" : "false",
        "aria-controls": "tab-panel",
        tabindex: tab.id === current ? "0" : "-1",
        onclick: () => {
          window.location.hash = tab.href;
        },
        onkeydown: (/** @type {Event} */ event) => {
          const key = /** @type {KeyboardEvent} */ (event).key;
          if (key !== "ArrowRight" && key !== "ArrowLeft") return;
          const index = tabs.findIndex((item) => item.id === tab.id);
          const next = tabs[(index + (key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
          window.location.hash = next.href;
        },
      }, tab.text),
    ),
  );
}

/**
 * @param {[string, Node | string][]} rows
 */
export function kv(rows) {
  return h("dl", { class: "kv" }, rows.flatMap(([term, value]) => [h("dt", null, term), h("dd", null, value)]));
}

/**
 * @template T
 * @typedef {Object} Column
 * @property {string} key
 * @property {string} label
 * @property {(row: T) => Node | string} cell
 * @property {boolean=} numeric
 * @property {boolean=} sortable
 */

/**
 * A table whose sortable headers are buttons and whose rows can be chosen
 * with the keyboard.
 * @template T
 * @param {{
 *   caption: string,
 *   columns: Column<T>[],
 *   groups: {label: string | null, rows: T[]}[],
 *   sort?: {key: string, descending: boolean},
 *   onSort?: (key: string) => void,
 *   rowKey?: (row: T) => string,
 *   selected?: string | null,
 *   onSelect?: (row: T) => void,
 *   empty?: string,
 *   tall?: boolean,
 * }} options
 */
export function dataTable(options) {
  const { caption, columns, groups, sort, onSort, rowKey, selected, onSelect, empty, tall } = options;
  const head = h(
    "tr",
    null,
    columns.map((column) => {
      const active = sort && sort.key === column.key;
      const attrs = { scope: "col", class: column.numeric ? "num" : null, "aria-sort": active && sort ? (sort.descending ? "descending" : "ascending") : null };
      if (!column.sortable || !onSort) return h("th", attrs, column.label);
      return h("th", attrs, h("button", { type: "button", onclick: () => onSort(column.key) }, column.label, active && sort ? (sort.descending ? " ↓" : " ↑") : ""));
    }),
  );
  const body = h("tbody");
  const total = groups.reduce((sum, group) => sum + group.rows.length, 0);
  if (!total) {
    body.append(h("tr", null, h("td", { colspan: columns.length, class: "muted" }, empty || "Nothing to show.")));
  }
  for (const group of groups) {
    if (!group.rows.length) continue;
    if (group.label) body.append(h("tr", null, h("th", { colspan: columns.length, scope: "colgroup", class: "group" }, `${group.label} (${group.rows.length})`)));
    for (const row of group.rows) {
      const key = rowKey ? rowKey(row) : "";
      const chosen = selected !== undefined && selected === key;
      const tr = h(
        "tr",
        {
          class: onSelect ? "row-link" : null,
          "aria-selected": onSelect ? (chosen ? "true" : "false") : null,
          tabindex: onSelect ? "0" : null,
        },
        columns.map((column) => h("td", { class: column.numeric ? "num" : null }, column.cell(row))),
      );
      if (onSelect) {
        tr.addEventListener("click", () => onSelect(row));
        tr.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            onSelect(row);
          }
        });
      }
      body.append(tr);
    }
  }
  return h("div", { class: `table-wrap${tall ? " tall" : ""}` }, h("table", null, h("caption", { class: "visually-hidden" }, caption), h("thead", null, head), body));
}
