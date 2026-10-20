// @ts-check
// Helpers every view uses: the page heading and the load wrapper.

import { banner, errorState, skeleton } from "../components.js";
import { h } from "../dom.js";

/** @typedef {import("../app.js").Context} Context */
/**
 * @template T
 * @typedef {import("../app.js").Load<T>} Load
 */

/**
 * The common wrapper for a view that needs one load: loading, error, or ready.
 * @template T
 * @param {Context} ctx
 * @param {"history" | "builds" | "users"} key
 * @param {(data: T) => Node} ready
 */
export function withLoad(ctx, key, ready) {
  const slot = /** @type {Load<T>} */ (ctx.state[key]);
  if (slot.status === "idle") {
    queueMicrotask(() => ctx.load(key));
    return skeleton(4);
  }
  if (slot.status === "loading" && !slot.data) return skeleton(4);
  if (slot.status === "error" && !slot.data) return errorState(/** @type {Error} */ (slot.error), () => ctx.load(key, true));
  const content = ready(/** @type {T} */ (slot.data));
  if (slot.status === "error" && slot.error) {
    return h("div", null, banner("warn", "Showing the last data loaded.", ` Refreshing failed: ${slot.error.message}`), content);
  }
  return content;
}

/**
 * @param {string} title
 * @param {string} [lead]
 * @param {Node | null} [actions]
 */
export function pageHead(title, lead, actions) {
  return h("header", { class: "page-head" }, h("div", null, h("h1", null, title), lead ? h("p", null, lead) : null), actions || null);
}
