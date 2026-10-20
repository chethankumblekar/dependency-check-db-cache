// @ts-check
import { stateBlock } from "../components.js";
import { h } from "../dom.js";
import { pageHead } from "./common.js";

/** @param {import("../app.js").Context} ctx */
export function renderNotFound(ctx) {
  return h(
    "div",
    null,
    pageHead("Page not found"),
    stateBlock({ iconName: "alert", title: "There is nothing at this address", body: `No page matches “${ctx.route.params.path || ""}”.`, action: h("a", { class: "btn", href: "#/" }, "Go to overview") }),
  );
}
