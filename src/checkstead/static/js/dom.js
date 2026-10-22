// @ts-check
// Element construction without innerHTML. Text is always set as text, so data
// from a scan report can never become markup.

/**
 * @typedef {string | number | Node | null | undefined | false} Child
 * @typedef {Record<string, string | number | boolean | null | undefined | EventListener>} Props
 */

/**
 * @param {string} tag
 * @param {Props | null} [props]
 * @param {...(Child | Child[])} children
 * @returns {HTMLElement}
 */
export function h(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), /** @type {EventListener} */ (value));
    } else if (key === "class") {
      node.className = String(value);
    } else if (value === true) {
      node.setAttribute(key, "");
    } else {
      node.setAttribute(key, String(value));
    }
  }
  append(node, children);
  return node;
}

/**
 * @param {Node} node
 * @param {(Child | Child[])[]} children
 */
export function append(node, children) {
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.appendChild(typeof child === "object" ? child : document.createTextNode(String(child)));
  }
}

const SVG = "http://www.w3.org/2000/svg";

/** Icon paths on a 16-unit grid, stroked with currentColor. */
const ICONS = {
  shield: "M8 1.8 13 3.6v4.2c0 3.2-2.1 5.4-5 6.4-2.9-1-5-3.2-5-6.4V3.6Z",
  check: "M3.5 8.4 6.6 11.5 12.5 4.5",
  alert: "M8 2.2 14.2 13H1.8ZM8 6.5v3M8 11.4v.1",
  cross: "M4 4l8 8M12 4l-8 8",
  dot: "M8 6.2a1.8 1.8 0 1 0 0 3.6 1.8 1.8 0 1 0 0-3.6",
  overview: "M2 2.5h5v5H2zM9 2.5h5v3H9zM9 7.5h5v6H9zM2 9.5h5v4H2z",
  scans: "M2.5 3h11M2.5 8h11M2.5 13h7",
  evidence: "M8 1.8 13 3.6v4.2c0 3.2-2.1 5.4-5 6.4-2.9-1-5-3.2-5-6.4V3.6ZM5.6 8.1 7.3 9.8 10.4 6.3",
  builds: "M3 3.5h4v4H3zM9 8.5h4v4H9zM5 7.5v3h4",
  people: "M5.5 7.2a2.2 2.2 0 1 0 0-4.4 2.2 2.2 0 0 0 0 4.4ZM1.8 13.2c.4-2.3 1.9-3.6 3.7-3.6s3.3 1.3 3.7 3.6M10.8 6.8a1.9 1.9 0 1 0 0-3.8M11.6 9.6c1.4.3 2.3 1.5 2.6 3.6",
  out: "M6 2.5H3v11h3M10 5l3 3-3 3M13 8H6",
  offline: "M2 2l12 12M5.2 8.6a4 4 0 0 1 5.1-.4M2.6 6.1A7.5 7.5 0 0 1 6 4.3M9.8 4.3a7.5 7.5 0 0 1 3.6 1.8M8 12.2v.1",
  lock: "M4 7.5h8v6H4zM5.5 7.5V5a2.5 2.5 0 0 1 5 0v2.5",
  clock: "M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11ZM8 5v3.2l2 1.3",
  github: "M6.2 13.2c-2.6.8-2.6-1.3-3.7-1.6M9.8 14.2v-2.1c0-.6 0-1.1-.4-1.5 1.9-.2 3.9-.9 3.9-4.2a3.3 3.3 0 0 0-.9-2.3 3.1 3.1 0 0 0 0-2.3s-.7-.2-2.4.9a8.2 8.2 0 0 0-4.3 0C4 1.6 3.3 1.8 3.3 1.8a3.1 3.1 0 0 0 0 2.3 3.3 3.3 0 0 0-.9 2.3c0 3.3 2 4 3.9 4.2-.4.4-.5.9-.4 1.5v2.1",
  microsoft: "M2.5 2.5h5v5h-5zM8.5 2.5h5v5h-5zM2.5 8.5h5v5h-5zM8.5 8.5h5v5h-5z",
  computer: "M2 3h12v8H2zM6 13.5h4M8 11v2.5",
  repos: "M4.5 2.5v11M11.5 2.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3M11.5 5.5c0 3-7 2.5-7 5.5",
  sync: "M13 3.5v3h-3M3 12.5v-3h3M12.6 6.5A5 5 0 0 0 3.7 5M3.4 9.5a5 5 0 0 0 8.9 1.5",
};

/** @typedef {keyof typeof ICONS} IconName */

/**
 * @param {IconName} name
 * @param {string} [label] When given, the icon is announced; otherwise it is decorative.
 * @returns {SVGSVGElement}
 */
export function icon(name, label) {
  const svg = /** @type {SVGSVGElement} */ (document.createElementNS(SVG, "svg"));
  svg.setAttribute("class", "icon");
  svg.setAttribute("viewBox", "0 0 16 16");
  if (label) {
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", label);
  } else {
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
  }
  const path = document.createElementNS(SVG, "path");
  path.setAttribute("d", ICONS[name]);
  svg.appendChild(path);
  return svg;
}

/**
 * Accept only http(s) links, resolved against this origin.
 * @param {string | null | undefined} value
 * @returns {string}
 */
export function safeHttpUrl(value) {
  if (!value) return "";
  try {
    const parsed = new URL(value, window.location.origin);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : "";
  } catch {
    return "";
  }
}
