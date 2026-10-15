"""Drift between two phase 1 scan reports."""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.history import diff_scans, history_payload, load_history, load_scan  # noqa: E402
from checkstead.ui import bind_server  # noqa: E402


def write_scan(directory: Path, project: str, dependencies: list[dict]) -> None:
    directory.mkdir(parents=True)
    (directory / "checkstead.txt").write_text(
        "engine: 13.0.0\n"
        "snapshot: 2026-10-06T01:02:03Z\n"
        "checksum: sha256:abc\n"
        f"project: {project}\n"
        "notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.\n",
        encoding="utf-8",
    )
    (directory / "dependency-check-report.json").write_text(
        json.dumps({"dependencies": dependencies}),
        encoding="utf-8",
    )


class HistoryTests(TestCase):
    def test_sample_scans_show_dependency_drift_without_score_source(self) -> None:
        scans = load_history(ROOT / "ui" / "scans")
        self.assertEqual([scan.project for scan in scans], ["fixture-a", "fixture-b"])
        self.assertEqual(scans[0].snapshot, scans[1].snapshot)
        self.assertEqual(scans[0].engine, "13.0.0")
        self.assertTrue(scans[0].revision)
        self.assertNotEqual(scans[0].revision, scans[1].revision)
        self.assertEqual(scans[0].author, "Cursor Agent")
        self.assertEqual(scans[1].author, "Cursor Agent")
        drift = diff_scans(scans[0], scans[1])
        self.assertEqual([item.name for item in drift.dependencies_added], ["com.google.code.gson:gson"])
        self.assertEqual(
            [item.name for item in drift.dependencies_removed],
            ["org.apache.commons:commons-lang3"],
        )
        self.assertEqual(len(drift.dependencies_changed), 1)
        before, after = drift.dependencies_changed[0]
        self.assertEqual(before.name, "com.google.guava:guava")
        self.assertEqual(before.version, "31.1-jre")
        self.assertEqual(after.version, "32.1.3-jre")
        self.assertEqual(drift.findings_added, [])
        self.assertEqual(drift.findings_removed, [])
        self.assertFalse(drift.score_source_available)
        payload = history_payload(scans)
        self.assertEqual(payload["later"], {"suppressions": [], "falsePositives": []})

    def test_score_source_is_shown_only_when_the_report_has_it(self) -> None:
        root = ROOT / "build" / "tests" / "score-source"
        if root.exists():
            import shutil
            shutil.rmtree(root)
        write_scan(
            root / "01",
            "one",
            [{
                "fileName": "demo.jar",
                "name": "dev.example:demo",
                "version": "1",
                "sha256": "aa",
                "vulnerabilities": [{"name": "CVE-2026-1", "cvssv3": {"baseScore": 5.4}}],
            }],
        )
        write_scan(
            root / "02",
            "two",
            [{
                "fileName": "demo.jar",
                "name": "dev.example:demo",
                "version": "1",
                "sha256": "aa",
                "vulnerabilities": [{
                    "name": "CVE-2026-1",
                    "cvssv3": {"baseScore": 7.1},
                    "scoreSource": "NVD",
                }],
            }],
        )
        scans = load_history(root)
        self.assertFalse(scans[0].has_score_source)
        self.assertTrue(scans[1].has_score_source)
        drift = diff_scans(scans[0], scans[1])
        self.assertTrue(drift.score_source_available)
        self.assertEqual(drift.findings_changed[0][0].cvss, {"3": "5.4"})
        self.assertEqual(drift.findings_changed[0][1].cvss, {"3": "7.1"})
        self.assertEqual(drift.findings_changed[0][1].score_source, "NVD")
        loaded = load_scan(root / "01")
        self.assertEqual(loaded.findings[0].score_source_present, False)

    def test_ui_serves_the_timeline(self) -> None:
        from checkstead.accounts import AccountStore
        from checkstead.identity import Identity

        data = ROOT / "build" / "tests" / "ui-session"
        if data.exists():
            import shutil
            shutil.rmtree(data)
        token, _user = AccountStore(data).sign_in(Identity("github", "7", "octocat", "The Octocat"))
        server = bind_server(ROOT / "ui" / "scans", "127.0.0.1", 0, data)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        page = urllib.request.urlopen(f"http://{host}:{port}/").read().decode()
        self.assertIn("Checkstead", page)
        self.assertIn("Suppressions", page)
        self.assertIn("Administration", page)
        self.assertIn('id="i-github"', page)
        self.assertIn('id="i-azure-devops"', page)
        self.assertIn('id="i-clock"', page)
        denied = urllib.request.Request(f"http://{host}:{port}/api/history")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(denied)
        self.assertEqual(caught.exception.code, 401)
        request = urllib.request.Request(
            f"http://{host}:{port}/api/history",
            headers={"Cookie": f"checkstead_session={token}"},
        )
        payload = json.load(urllib.request.urlopen(request))
        changed = payload["drifts"][0]["dependencies"]["changed"]
        self.assertEqual(changed[0]["before"]["version"], "31.1-jre")
        self.assertEqual(changed[0]["after"]["version"], "32.1.3-jre")
        self.assertFalse(payload["drifts"][0]["scores"]["available"])
        self.assertEqual(payload["scans"][0]["scoreLines"], [])

    def test_a_score_line_names_version_score_and_source(self) -> None:
        root = ROOT / "build" / "tests" / "score-line"
        if root.exists():
            import shutil
            shutil.rmtree(root)
        directory = root / "01"
        directory.mkdir(parents=True)
        (directory / "checkstead.txt").write_text(
            "engine: 13.0.0\n"
            "snapshot: 2026-10-06T01:02:03Z\n"
            "checksum: sha256:abc\n"
            "project: scored\n"
            "notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.\n"
            "finding: CVE-2020-8908 cvss=3 score=5.5 source=NVD vector=none enrichment=present kev=no dependency=guava-16.0.1.jar\n",
            encoding="utf-8",
        )
        (directory / "dependency-check-report.json").write_text('{"dependencies": []}\n', encoding="utf-8")
        scan = load_scan(directory)
        self.assertEqual(
            scan.score_lines,
            ["finding: CVE-2020-8908 cvss=3 score=5.5 source=NVD vector=none enrichment=present kev=no dependency=guava-16.0.1.jar"],
        )
        payload = history_payload([scan])
        self.assertEqual(payload["scans"][0]["scoreLines"], scan.score_lines)
