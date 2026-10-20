// Pure modules: routing, formatting, the request client, and the model.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, kindForStatus, request } from "../../src/checkstead/static/js/api.js";
import { ageDays, freshness, relativeTime, severity, severityLabel, shortDigest, scanName, utcLabel } from "../../src/checkstead/static/js/format.js";
import { attention, evidenceChain, latestScans, severityCounts } from "../../src/checkstead/static/js/model.js";
import { href, parseRoute } from "../../src/checkstead/static/js/router.js";
import { NOW, finding, history, scan } from "./helpers.mjs";

test("routes parse and round-trip", () => {
  assert.deepEqual(parseRoute(""), { name: "overview", params: {} });
  assert.deepEqual(parseRoute("#/"), { name: "overview", params: {} });
  assert.deepEqual(parseRoute("#/scans"), { name: "scans", params: {} });
  assert.deepEqual(parseRoute("#/scans/a%20b"), { name: "scan", params: { id: "a b" } });
  assert.deepEqual(parseRoute("#/scans/x/changes"), { name: "scan", params: { id: "x", tab: "changes" } });
  assert.equal(parseRoute("#/scans/x/unknown").name, "not-found");
  assert.equal(parseRoute("#/nope").name, "not-found");
  assert.deepEqual(parseRoute("#/scans/%E0%A4%A"), { name: "scan", params: { id: "%E0%A4%A" } });
  assert.equal(href("overview"), "#/");
  assert.equal(href("scan", { id: "a/b", tab: "findings" }), "#/scans/a%2Fb");
  assert.equal(href("scan", { id: "a/b", tab: "evidence" }), "#/scans/a%2Fb/evidence");
  assert.deepEqual(parseRoute(href("scan", { id: "a/b", tab: "evidence" })), { name: "scan", params: { id: "a/b", tab: "evidence" } });
});

test("freshness follows the scan client's day rules", () => {
  assert.equal(ageDays("2026-10-20T00:01:00Z", NOW), 0);
  assert.equal(freshness("2026-10-19T23:59:00Z", NOW).freshness, "current");
  assert.equal(freshness("2026-10-18T05:00:00Z", NOW).freshness, "aging");
  assert.equal(freshness("2026-10-13T05:00:00Z", NOW).freshness, "aging");
  assert.equal(freshness("2026-10-12T05:00:00Z", NOW).freshness, "stale");
  assert.deepEqual(freshness("not a time", NOW), { freshness: "unknown", age: null });
  assert.equal(relativeTime("2026-10-20T15:00:00Z", NOW), "3 hours ago");
  assert.equal(relativeTime("", NOW), "time not recorded");
  assert.equal(utcLabel("2026-10-20T05:32:17Z"), "20 Oct 2026, 05:32 UTC");
});

test("severity bands never call a missing score low", () => {
  assert.equal(severity("9.0"), "critical");
  assert.equal(severity(7), "high");
  assert.equal(severity("4.0"), "medium");
  assert.equal(severity("0.1"), "low");
  assert.equal(severity(undefined), "none");
  assert.equal(severity(""), "none");
  assert.equal(severity("n/a"), "none");
  assert.equal(severityLabel("none"), "No score");
  assert.equal(shortDigest("sha256:" + "f".repeat(64)), "ffffffffffff…");
  assert.equal(shortDigest(null), "not recorded");
  assert.equal(scanName({ project: "p", id: "x", pullRequest: "12" }), "p #12");
});

test("request maps failures to typed errors", async () => {
  const answer = (status, body) => async () => new Response(body, { status });
  assert.deepEqual(await request("/x", {}, answer(200, '{"ok":true}')), { ok: true });
  await assert.rejects(request("/x", {}, answer(401, '{"error":"Sign in first."}')), (error) => error instanceof ApiError && error.kind === "auth" && error.message === "Sign in first.");
  await assert.rejects(request("/x", {}, answer(500, "oops")), (error) => error.kind === "server" && /HTTP 500/.test(error.message));
  await assert.rejects(request("/x", {}, async () => { throw new TypeError("network"); }), (error) => error.kind === "offline");
  assert.equal(kindForStatus(403), "forbidden");
  assert.equal(kindForStatus(404), "not-found");
  assert.equal(kindForStatus(413), "invalid");
});

test("latest scans keep one per project, branch and pull request", () => {
  const scans = [scan("a"), scan("b"), scan("c", { branch: "dev" }), scan("d", { pullRequest: "4" })];
  assert.deepEqual(latestScans(scans).map((s) => s.id), ["d", "c", "b"]);
});

test("counts and the evidence chain state only what was recorded", () => {
  const counts = severityCounts(history().scans[1].findings);
  assert.deepEqual(counts, { critical: 2, high: 1, medium: 1, low: 0, none: 1, kev: 1, total: 5 });
  const signed = evidenceChain(scan("s"), NOW);
  assert.deepEqual(signed.map((link) => link.state), ["verified", "verified", "verified", "verified"]);
  const old = evidenceChain(scan("o", { snapshot: "2026-09-01T00:00:00Z", authenticity: "unsigned", checksum: "", engine: "" }), NOW);
  assert.deepEqual(old.map((link) => link.state), ["fail", "fail", "unknown", "unknown"]);
  const legacy = evidenceChain(scan("l", { authenticity: null }), NOW);
  assert.equal(legacy[1].verdict, "Not recorded");
});

test("attention lists exploited and critical findings first", () => {
  const items = attention(history(), NOW);
  assert.deepEqual(items.map((item) => item.level), ["fail", "fail", "warn"]);
  assert.match(items[0].title, /1 finding actively exploited/);
  assert.match(items[1].title, /2 critical findings/);
  assert.match(items[2].title, /2 new findings/);
  const stale = attention({ notice: "", scans: [scan("s", { snapshot: "2026-09-01T00:00:00Z", authenticity: "unsigned", findings: [finding("CVE-1", 3)] })], drifts: [] }, NOW);
  assert.deepEqual(stale.map((item) => item.href), ["#/scans/s/evidence", "#/scans/s/evidence"]);
  assert.deepEqual(attention({ notice: "", scans: [], drifts: [] }, NOW), []);
});
