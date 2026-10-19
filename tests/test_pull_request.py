"""Pull request comparison, the one comment, and the report tag.

No vulnerability feed is contacted. The comment step talks to a local stand-in
for the GitHub issues API.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from checkstead.history import history_payload, load_scan  # noqa: E402
from checkstead.score import (  # noqa: E402
    COMMENT_MARKER,
    evaluate_report,
    finding_identity,
    partition_findings,
    policy_failures,
    render_pull_request_comment,
)
from test_phase1 import FixtureServer, manifest_for, run_cli, write_zip  # noqa: E402


def _v3(score: float, source: str | None = None) -> dict:
    block = {
        "baseScore": score,
        "version": "3.1",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
    }
    if source:
        block["source"] = source
    return {"cvssv3": block}


def _package(
    name: str,
    version: str,
    vulns: list[dict],
    *,
    fuzzy: dict | None = None,
    cpe: bool = True,
) -> dict:
    packages = [{"id": f"pkg:npm/{name}@{version}", "confidence": "HIGHEST"}]
    vulnerability_ids = []
    if cpe:
        vulnerability_ids.append(
            {"id": f"cpe:2.3:a:{name}:{name}:{version}:*:*:*:*:*:*:*", "confidence": "HIGHEST"}
        )
    if fuzzy is not None:
        packages.append(fuzzy)
        vulnerability_ids.append(fuzzy)
    return {
        "fileName": f"{name}:{version}",
        "packages": packages,
        "vulnerabilityIds": vulnerability_ids,
        "vulnerabilities": vulns,
    }


def _vuln(name: str, source: str, scores: dict, *, kev: bool = False, cpe: str | None = None) -> dict:
    vulnerability: dict = {"name": name, "source": source}
    vulnerability.update(scores)
    if kev:
        vulnerability["knownExploitedVulnerability"] = {"Name": name}
    if cpe:
        vulnerability["vulnerableSoftware"] = [{"software": {"id": cpe}}]
    return vulnerability


class PullRequestCompareTests(TestCase):
    def _trees(self) -> tuple[dict, dict]:
        fuzzy = {
            "id": "cpe:2.3:a:nextgen:nextgen:1.0:*:*:*:*:*:*:*",
            "confidence": "LOW",
            "notes": "fuzzy match",
        }
        head = {
            "dependencies": [
                _package(
                    "next",
                    "16.3.5",
                    [
                        _vuln("CVE-FUZZY", "NVD", _v3(9.8)),
                        _vuln("GHSA-next", "NPM", _v3(5.3)),
                        _vuln("GHSA-new", "NPM", _v3(8.8)),
                    ],
                    fuzzy=fuzzy,
                    cpe=False,
                ),
                _package(
                    "braces",
                    "3.0.2",
                    [
                        _vuln(
                            "CVE-REAL",
                            "NVD",
                            _v3(7.5),
                            cpe="cpe:2.3:a:braces:braces:3.0.2:*:*:*:*:*:*:*",
                        )
                    ],
                ),
            ]
        }
        base = {
            "dependencies": [
                _package("next", "16.3.5", [_vuln("GHSA-next", "NPM", _v3(5.3))]),
                {
                    "fileName": "node_modules/braces/package.json",
                    "packages": [{"id": "pkg:npm/braces@3.0.2", "confidence": "HIGHEST"}],
                    "vulnerabilityIds": [
                        {"id": "cpe:2.3:a:braces:braces:3.0.2:*:*:*:*:*:*:*", "confidence": "HIGHEST"}
                    ],
                    "vulnerabilities": [
                        _vuln(
                            "CVE-REAL",
                            "OSSINDEX",
                            _v3(9.1),
                            cpe="cpe:2.3:a:braces:braces:3.0.2:*:*:*:*:*:*:*",
                            kev=True,
                        )
                    ],
                },
                _package("lodash", "4.17.21", [_vuln("CVE-OLD", "NPM", _v3(9.8))]),
            ]
        }
        return head, base

    def test_introduced_is_package_identity_and_vulnerability_id(self) -> None:
        head, base = self._trees()
        roles_note = None
        head_scored = evaluate_report(
            head, policy="prefer-newest", threshold=7, fail_on_kev=True, fail_unscored=True, roles=roles_note
        )
        base_scored = evaluate_report(
            base, policy="prefer-newest", threshold=7, fail_on_kev=True, fail_unscored=True
        )
        joined = "\n".join(head_scored.lines)
        self.assertNotIn("CVE-FUZZY", joined)
        introduced, existing = partition_findings(head_scored.findings, base_scored.findings)
        self.assertEqual([item.identifier for item in introduced], ["GHSA-new"])
        self.assertEqual([item.identifier for item in existing], ["GHSA-next", "CVE-REAL"])
        new = introduced[0]
        self.assertEqual(finding_identity(new), ("next", "16.3.5", "GHSA-new"))
        self.assertEqual((new.relationship, new.scope), ("direct", "production"))
        self.assertEqual(new.choice.source, "NPM")
        real = next(item for item in existing if item.identifier == "CVE-REAL")
        self.assertEqual(finding_identity(real), ("braces", "3.0.2", "CVE-REAL"))
        self.assertEqual(real.choice.source, "NVD")
        self.assertEqual((real.relationship, real.scope), ("direct", "production"))
        failures = policy_failures(
            introduced, policy="prefer-newest", threshold=7, fail_on_kev=True, fail_unscored=True
        )
        self.assertEqual(
            failures,
            ["prefer-newest failed the build on GHSA-new cvss 3.1 score 8.8 source NPM"],
        )
        self.assertNotIn("CVE-REAL", "\n".join(failures))
        self.assertNotIn("GHSA-next", "\n".join(failures))
        quiet = policy_failures(
            introduced, policy="prefer-newest", threshold=None, fail_on_kev=False, fail_unscored=False
        )
        self.assertEqual(quiet, [])

    def test_a_version_change_is_introduced_and_kev_on_the_base_is_not(self) -> None:
        head = {
            "dependencies": [
                _package("leftpad", "1.0.0", [_vuln("CVE-KEV", "NVD", _v3(4.0), kev=True)]),
                _package("fresh", "2.0.0", [_vuln("CVE-NEW", "NVD", {}, kev=False)]),
            ]
        }
        base = {
            "dependencies": [
                _package("leftpad", "1.0.0", [_vuln("CVE-KEV", "NVD", _v3(4.0), kev=True)]),
            ]
        }
        head_scored = evaluate_report(
            head, policy="highest", threshold=9, fail_on_kev=True, fail_unscored=True
        )
        base_scored = evaluate_report(
            base, policy="highest", threshold=9, fail_on_kev=True, fail_unscored=True
        )
        introduced, existing = partition_findings(head_scored.findings, base_scored.findings)
        self.assertEqual([item.identifier for item in existing], ["CVE-KEV"])
        self.assertEqual([item.identifier for item in introduced], ["CVE-NEW"])
        failures = policy_failures(
            introduced, policy="highest", threshold=9, fail_on_kev=True, fail_unscored=True
        )
        self.assertEqual(failures, ["highest failed the build on CVE-NEW no score"])
        bumped = evaluate_report(
            {"dependencies": [_package("leftpad", "2.0.0", [_vuln("CVE-KEV", "NVD", _v3(4.0), kev=True)])]},
            policy="prefer-newest",
            threshold=None,
            fail_on_kev=False,
            fail_unscored=False,
        )
        introduced, existing = partition_findings(bumped.findings, base_scored.findings)
        self.assertEqual([item.identifier for item in introduced], ["CVE-KEV"])
        self.assertEqual(existing, [])
        self.assertEqual(finding_identity(introduced[0]), ("leftpad", "2.0.0", "CVE-KEV"))

    def test_comment_and_report_name_the_pull_request(self) -> None:
        head, base = self._trees()
        head_scored = evaluate_report(
            head, policy="prefer-newest", threshold=7, fail_on_kev=False, fail_unscored=False
        )
        base_scored = evaluate_report(
            base, policy="prefer-newest", threshold=7, fail_on_kev=False, fail_unscored=False
        )
        introduced, existing = partition_findings(head_scored.findings, base_scored.findings)
        comment = render_pull_request_comment("42", "2026-10-15T05:24:17Z", introduced, existing, [])
        self.assertTrue(comment.startswith(COMMENT_MARKER))
        self.assertIn("Checkstead pull request #42", comment)
        self.assertIn("GHSA-new on next 16.3.5, direct, production, source NPM, score 8.8", comment)
        self.assertIn("CVE-REAL on braces 3.0.2, direct, production, source NVD, score 7.5", comment)
        self.assertIn("Already on the base", comment)
        self.assertIn("The build passed", comment)
        self.assertNotIn("CVE-FUZZY", comment)
        self.assertNotIn("CVE-OLD", comment)
        root = ROOT / "build" / "tests" / "pr-tag"
        shutil.rmtree(root, ignore_errors=True)
        report = root / "out"
        report.mkdir(parents=True)
        (report / "checkstead.txt").write_text(
            "engine: 13.0.0\n"
            "snapshot: 2026-10-15T05:24:17Z\n"
            "checksum: sha256:abc\n"
            "project: my-service\n"
            "pull-request: 42\n"
            "notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.\n"
            + "\n".join(head_scored.lines)
            + "\n",
            encoding="utf-8",
        )
        (report / "dependency-check-report.json").write_text(json.dumps(head), encoding="utf-8")
        scan = load_scan(report)
        self.assertEqual(scan.pull_request, "42")
        payload = history_payload([scan])
        self.assertEqual(payload["scans"][0]["pullRequest"], "42")
        page = (ROOT / "src" / "checkstead" / "ui_page.html").read_text(encoding="utf-8")
        self.assertIn("function scanName(scan)", page)
        self.assertIn('name + " #" + scan.pullRequest', page)
        self.assertIn("scanName(scan)", page)

    def test_one_snapshot_scans_head_and_base_and_fails_only_introduced(self) -> None:
        root = ROOT / "build" / "tests" / "pr-scan"
        shutil.rmtree(root, ignore_errors=True)
        head = root / "head"
        base = root / "base"
        head.mkdir(parents=True)
        base.mkdir(parents=True)
        head_report, base_report = self._trees()
        (head / "dependency-check-report.json").write_text(json.dumps(head_report), encoding="utf-8")
        (base / "dependency-check-report.json").write_text(json.dumps(base_report), encoding="utf-8")
        (head / "package.json").write_text(
            json.dumps({"dependencies": {"next": "16.3.5"}, "devDependencies": {"braces": "3.0.2"}}),
            encoding="utf-8",
        )
        engine = root / "dependency-check.sh"
        engine.write_text(
            "#!/bin/sh\n"
            "out=\n"
            "scan=\n"
            "prev=\n"
            'for arg in "$@"; do\n'
            '  if [ "$prev" = "--out" ]; then out=$arg; fi\n'
            '  if [ "$prev" = "--scan" ]; then scan=$arg; fi\n'
            "  prev=$arg\n"
            "done\n"
            'mkdir -p "$out"\n'
            'printf \'%s\\n\' "$@" > "$out/engine-argv.txt"\n'
            'if [ -f "$scan/dependency-check-report.json" ]; then\n'
            '  cp "$scan/dependency-check-report.json" "$out/dependency-check-report.json"\n'
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        engine.chmod(0o755)
        blob = root / "db.zip"
        write_zip(blob, "pr")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(blob, "2026-10-15T05:24:17Z")
        server.zip_bytes = blob.read_bytes()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["CHECKSTEAD_TODAY"] = "2026-10-15"
        env["NVD_API_KEY"] = "unused"
        out = root / "out"
        failed = run_cli(
            [
                "scan",
                "--scan",
                str(head),
                "--base",
                str(base),
                "--pull-request",
                "42",
                "--project",
                "my-service",
                "--out",
                str(out),
                "--cache",
                str(root / "cache"),
                "--engine",
                str(engine),
                "--config",
                str(self._config(root, server.manifest_url, "7")),
            ],
            env,
            root,
        )
        self.assertEqual(failed.returncode, 3, failed.stderr)
        self.assertIn("GHSA-new", failed.stderr)
        self.assertNotIn("CVE-REAL", failed.stderr)
        report = (out / "checkstead.txt").read_text(encoding="utf-8")
        self.assertIn("pull-request: 42", report)
        self.assertIn("relationship=direct scope=production", report)
        self.assertIn("dependency=braces:3.0.2", report)
        self.assertIn("relationship=direct scope=dev", report)
        self.assertNotIn("CVE-FUZZY", report)
        comment = (out / "checkstead-comment.md").read_text(encoding="utf-8")
        self.assertIn("Checkstead pull request #42", comment)
        self.assertIn("GHSA-new on next 16.3.5, direct, production, source NPM, score 8.8", comment)
        self.assertIn("CVE-REAL on braces 3.0.2, direct, dev, source NVD, score 7.5", comment)
        self.assertIn("The build failed", comment)
        commands = (out / "checkstead-command.txt").read_text(encoding="utf-8").split("\n\n")
        self.assertEqual(len(commands), 2)
        for command in commands:
            self.assertIn("--noupdate", command)
            self.assertNotIn("--nvdApiKey", command)
            self.assertNotIn("nvdApiKey", command)
            self.assertNotIn("--suppression", command)
        data_args = []
        for command in commands:
            parts = command.splitlines()
            data_args.append(parts[parts.index("--data") + 1])
        self.assertEqual(data_args[0], data_args[1])
        self.assertEqual(server.paths.count("/manifest.json"), 1)
        for host in server.hosts:
            self.assertNotIn("services.nvd.nist.gov", host)
        scan = load_scan(out)
        self.assertEqual(scan.pull_request, "42")
        self.assertEqual(scan.project, "my-service")

        quiet = run_cli(
            [
                "scan",
                "--scan",
                str(head),
                "--base",
                str(base),
                "--pull-request",
                "42",
                "--project",
                "my-service",
                "--out",
                str(root / "quiet"),
                "--cache",
                str(root / "cache"),
                "--engine",
                str(engine),
                "--config",
                str(self._config(root, server.manifest_url, "")),
            ],
            env,
            root,
        )
        self.assertEqual(quiet.returncode, 0, quiet.stderr)
        quiet_comment = (root / "quiet" / "checkstead-comment.md").read_text(encoding="utf-8")
        self.assertIn("The build passed", quiet_comment)
        self.assertIn("pull request #42", quiet_comment)

    def test_without_a_base_the_policy_still_fails_the_build(self) -> None:
        root = ROOT / "build" / "tests" / "pr-plain"
        shutil.rmtree(root, ignore_errors=True)
        head = root / "head"
        head.mkdir(parents=True)
        head_report, _base = self._trees()
        (head / "dependency-check-report.json").write_text(json.dumps(head_report), encoding="utf-8")
        engine = root / "dependency-check.sh"
        engine.write_text(
            "#!/bin/sh\n"
            "out=\n"
            "scan=\n"
            "prev=\n"
            'for arg in "$@"; do\n'
            '  if [ "$prev" = "--out" ]; then out=$arg; fi\n'
            '  if [ "$prev" = "--scan" ]; then scan=$arg; fi\n'
            "  prev=$arg\n"
            "done\n"
            'mkdir -p "$out"\n'
            'cp "$scan/dependency-check-report.json" "$out/dependency-check-report.json"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        engine.chmod(0o755)
        blob = root / "db.zip"
        write_zip(blob, "plain")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(blob, "2026-10-15T05:24:17Z")
        server.zip_bytes = blob.read_bytes()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["CHECKSTEAD_TODAY"] = "2026-10-15"
        completed = run_cli(
            [
                "scan",
                "--scan",
                str(head),
                "--out",
                str(root / "out"),
                "--cache",
                str(root / "cache"),
                "--engine",
                str(engine),
                "--config",
                str(self._config(root, server.manifest_url, "7")),
            ],
            env,
            root,
        )
        self.assertEqual(completed.returncode, 3, completed.stderr)
        self.assertIn("CVE-REAL", completed.stderr)
        self.assertFalse((root / "out" / "checkstead-comment.md").exists())
        report = (root / "out" / "checkstead.txt").read_text(encoding="utf-8")
        self.assertNotIn("pull-request:", report)

    def test_the_action_updates_one_comment_with_the_workflow_token(self) -> None:
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "pr-comment.py").read_text(encoding="utf-8")
        self.assertIn("github.token", action)
        self.assertIn("scripts/pr-comment.py", action)
        self.assertIn("--pull-request", action)
        self.assertIn("--base", action)
        self.assertIn("pull/${PR_NUMBER}/head", action)
        self.assertIn("GITHUB_REF_NAME", action)
        self.assertIn("GITHUB_SHA", action)
        self.assertIn("safe.directory", action)
        self.assertIn("--revision", action)
        self.assertNotIn("source.txt", action)
        entry = (ROOT / "scripts" / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("GITHUB_REF_NAME", entry)
        self.assertIn("GITHUB_SHA", entry)
        self.assertIn("--revision", entry)
        self.assertNotIn("source.txt", entry)
        self.assertIn(
            "github/codeql-action/upload-sarif@ce5e7eeac396d720fe2d802714996c8ce561e311",
            action,
        )
        self.assertIn("branch:", readme)
        self.assertIn("description:", readme)
        self.assertNotIn("NVD_API_KEY", action)
        self.assertNotIn("nvdApiKey", action)
        self.assertNotIn("services.nvd.nist.gov", action)
        self.assertNotIn("\n  token:", action)
        self.assertIn("pull-requests: write", readme)
        self.assertNotIn("paste", readme.lower())
        self.assertIn("GITHUB_TOKEN", script)
        self.assertNotIn("paste", script.lower())
        self.assertNotIn("input(", script)
        server = _CommentServer()
        self.addCleanup(server.close)
        comment = ROOT / "build" / "tests" / "comment.md"
        comment.parent.mkdir(parents=True, exist_ok=True)
        comment.write_text(
            f"{COMMENT_MARKER}\nCheckstead pull request #42\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = "workflow-token"
        env["GITHUB_REPOSITORY"] = "chethankumblekar/dependency-check-db-cache"
        env["PR_NUMBER"] = "42"
        env["COMMENT_FILE"] = str(comment)
        env["GITHUB_API_URL"] = server.url
        first = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "pr-comment.py")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        comment.write_text(
            f"{COMMENT_MARKER}\nCheckstead pull request #42\nupdated\n",
            encoding="utf-8",
        )
        second = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "pr-comment.py")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(server.comments), 1)
        self.assertEqual(server.comments[0]["id"], 7)
        self.assertIn("updated", server.comments[0]["body"])
        self.assertIn("pull request #42", server.comments[0]["body"])
        self.assertEqual(server.methods, ["GET", "POST", "GET", "PATCH"])
        self.assertTrue(all(item == "Bearer workflow-token" for item in server.authorizations))
        self.assertNotIn("workflow-token", first.stdout + first.stderr + second.stdout + second.stderr)

        server.comments.clear()
        server.methods.clear()
        for index in range(100):
            server.comments.append({"id": 1000 + index, "body": "other"})
        server.comments.append({"id": 55, "body": f"{COMMENT_MARKER}\nCheckstead pull request #9\n"})
        third = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "pr-comment.py")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(third.returncode, 0, third.stderr)
        self.assertIn("PATCH", server.methods)
        self.assertNotIn("POST", server.methods)
        self.assertEqual(server.patched, 55)

    def _config(self, root: Path, url: str, threshold: str) -> Path:
        path = root / "checkstead.yml"
        path.write_text(
            f"snapshot: {url}\nscorePolicy: prefer-newest\nthreshold: {threshold}\n"
            "failOnKev: false\nfailUnscored: false\nprivateSuppressions:\n",
            encoding="utf-8",
        )
        return path


class _CommentServer:
    def __init__(self) -> None:
        outer = self
        self.comments: list[dict] = []
        self.methods: list[str] = []
        self.authorizations: list[str] = []
        self.patched: int | None = None

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record("GET")
                page = int(parse_qs(urlparse(self.path).query).get("page", ["1"])[0])
                start = (page - 1) * 100
                self._json(outer.comments[start : start + 100])

            def do_POST(self):
                self._record("POST")
                payload = self._body()
                outer.comments.append({"id": 7, "body": payload["body"]})
                self._json({"id": 7, "body": payload["body"]})

            def do_PATCH(self):
                self._record("PATCH")
                payload = self._body()
                comment_id = int(self.path.rstrip("/").rsplit("/", 1)[-1])
                outer.patched = comment_id
                for comment in outer.comments:
                    if comment["id"] == comment_id:
                        comment["body"] = payload["body"]
                self._json({"id": comment_id, "body": payload["body"]})

            def _record(self, method: str) -> None:
                outer.methods.append(method)
                outer.authorizations.append(self.headers.get("Authorization", ""))

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(length).decode("utf-8"))

            def _json(self, payload) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt, *args):
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        self.url = f"http://{host}:{port}"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
