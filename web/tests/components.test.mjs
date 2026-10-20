// Components in a jsdom document.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError } from "../../src/checkstead/static/js/api.js";
import { dataTable, errorState, severityMark, tabs } from "../../src/checkstead/static/js/components.js";
import { h, safeHttpUrl } from "../../src/checkstead/static/js/dom.js";
import { freshDom } from "./helpers.mjs";

test("h() sets text, never markup", () => {
  freshDom();
  const node = h("p", { title: "<b>x</b>" }, "<img src=x onerror=alert(1)>");
  assert.equal(node.querySelector("img"), null);
  assert.equal(node.textContent, "<img src=x onerror=alert(1)>");
});

test("only http and https links are followed", () => {
  freshDom();
  assert.equal(safeHttpUrl("https://nvd.nist.gov/vuln/detail/CVE-1"), "https://nvd.nist.gov/vuln/detail/CVE-1");
  assert.equal(safeHttpUrl("javascript:alert(1)"), "");
  assert.equal(safeHttpUrl("data:text/html,x"), "");
});

test("severity is said in words, not colour alone", () => {
  freshDom();
  assert.match(severityMark("9.8").textContent, /Critical/);
  assert.match(severityMark("9.8").textContent, /9\.8/);
  assert.match(severityMark(undefined).textContent, /No score/);
});

test("data tables expose sort state and keyboard selection", () => {
  freshDom();
  const picked = [];
  const sorted = [];
  const table = dataTable({
    caption: "Findings",
    columns: [{ key: "id", label: "ID", sortable: true, cell: (row) => row.id }, { key: "n", label: "N", numeric: true, cell: (row) => String(row.n) }],
    groups: [{ label: "Direct", rows: [{ id: "a", n: 1 }, { id: "b", n: 2 }] }],
    sort: { key: "id", descending: true },
    onSort: (key) => sorted.push(key),
    rowKey: (row) => row.id,
    selected: "b",
    onSelect: (row) => picked.push(row.id),
  });
  document.body.append(table);
  const th = table.querySelector("th[aria-sort]");
  assert.equal(th.getAttribute("aria-sort"), "descending");
  th.querySelector("button").click();
  assert.deepEqual(sorted, ["id"]);
  assert.match(table.querySelector("th.group").textContent, /Direct \(2\)/);
  const rows = table.querySelectorAll("tbody tr[tabindex='0']");
  assert.equal(rows.length, 2);
  assert.equal(rows[1].getAttribute("aria-selected"), "true");
  rows[0].dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  rows[1].dispatchEvent(new KeyboardEvent("keydown", { key: " ", bubbles: true }));
  assert.deepEqual(picked, ["a", "b"]);
});

test("an empty table says why it is empty", () => {
  freshDom();
  const table = dataTable({ caption: "x", columns: [{ key: "a", label: "A", cell: () => "" }], groups: [{ label: null, rows: [] }], empty: "No findings in this scan." });
  assert.match(table.textContent, /No findings in this scan\./);
});

test("tabs move with arrow keys", () => {
  freshDom();
  const list = tabs("Scan", [{ id: "a", text: "A", href: "#/a" }, { id: "b", text: "B", href: "#/b" }], "a");
  document.body.append(list);
  const items = list.querySelectorAll("[role=tab]");
  assert.equal(items[0].getAttribute("aria-selected"), "true");
  items[0].focus();
  assert.equal(items[1].getAttribute("tabindex"), "-1");
  items[0].dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowRight", bubbles: true }));
  assert.equal(window.location.hash, "#/b");
  items[0].dispatchEvent(new KeyboardEvent("keydown", { key: "ArrowLeft", bubbles: true }));
  assert.equal(window.location.hash, "#/b");
});

test("error states name the cause and offer a retry", () => {
  freshDom();
  let retried = 0;
  const offline = errorState(new ApiError("offline", "The server could not be reached."), () => { retried += 1; });
  assert.match(offline.textContent, /could not be reached/i);
  offline.querySelector("button").click();
  assert.equal(retried, 1);
  const forbidden = errorState(new ApiError("forbidden", "Administrators only.", 403), () => {});
  assert.match(forbidden.textContent, /do not have access/);
  assert.equal(forbidden.querySelector("button"), null);
});
