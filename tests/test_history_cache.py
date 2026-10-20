"""The timeline history is rebuilt only when a scan changes, and served compressed."""

from __future__ import annotations

import gzip
import json
import os
import shutil
import sys
import time
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead import ui  # noqa: E402
from checkstead.ui import HistoryCache  # noqa: E402


class HistoryCacheTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "history-cache" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.copytree(ROOT / "ui" / "scans", self.root)

    def test_an_unchanged_directory_is_not_parsed_again(self) -> None:
        cache = HistoryCache(self.root)
        with mock.patch.object(ui, "load_history", wraps=ui.load_history) as loader:
            first = cache.body()
            second = cache.body()
        self.assertEqual(loader.call_count, 1)
        self.assertIs(first, second)
        self.assertIn("scans", json.loads(first.raw))
        self.assertEqual(gzip.decompress(first.gzipped), first.raw)

    def test_a_new_or_changed_scan_rebuilds_it(self) -> None:
        cache = HistoryCache(self.root)
        before = json.loads(cache.body().raw)
        source = sorted(path for path in self.root.iterdir() if path.is_dir())[0]
        shutil.copytree(source, self.root / "99-added")
        after = json.loads(cache.body().raw)
        self.assertEqual(len(after["scans"]), len(before["scans"]) + 1)
        report = self.root / "99-added" / "checkstead.txt"
        stamp = time.time() + 5
        report.write_text(report.read_text(encoding="utf-8").replace("project: ", "project: renamed-"), encoding="utf-8")
        os.utime(report, (stamp, stamp))
        renamed = json.loads(cache.body().raw)
        self.assertIn("renamed-", json.dumps(renamed))

    def test_a_removed_scan_rebuilds_it(self) -> None:
        cache = HistoryCache(self.root)
        count = len(json.loads(cache.body().raw)["scans"])
        victim = sorted(path for path in self.root.iterdir() if path.is_dir())[0]
        shutil.rmtree(victim)
        self.assertEqual(len(json.loads(cache.body().raw)["scans"]), count - 1)


class SummaryAndScanTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "history-summary" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        shutil.copytree(ROOT / "ui" / "scans", self.root)

    def test_the_summary_drops_dependency_lists_and_keeps_counts(self) -> None:
        cache = HistoryCache(self.root)
        full = json.loads(cache.body().raw)
        summary = json.loads(cache.summary().raw)
        self.assertEqual([scan["id"] for scan in summary["scans"]], [scan["id"] for scan in full["scans"]])
        for short, long in zip(summary["scans"], full["scans"]):
            self.assertNotIn("dependencies", short)
            self.assertEqual(short["dependencyCount"], len(long["dependencies"]))
            self.assertEqual(short["findings"], long["findings"])
        for short, long in zip(summary["drifts"], full["drifts"]):
            self.assertNotIn("dependencies", short)
            self.assertEqual(short["findings"], long["findings"])
            self.assertEqual(short["dependencyCounts"]["added"], len(long["dependencies"]["added"]))

    def test_one_scan_comes_back_in_full_with_its_drift(self) -> None:
        cache = HistoryCache(self.root)
        full = json.loads(cache.body().raw)
        last = full["scans"][-1]
        body = json.loads(cache.scan(last["id"]).raw)
        self.assertEqual(body["scan"], last)
        self.assertEqual(body["drift"], next((d for d in full["drifts"] if d["after"] == last["id"]), None))
        self.assertIsNone(cache.scan("no-such-scan"))
        self.assertIsNone(cache.scan("../01-fixture-a"))
