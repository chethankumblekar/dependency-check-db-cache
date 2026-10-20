"""Reports record the snapshot's signature status, and the timeline exposes it with KEV and policy."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.history import history_payload, load_history  # noqa: E402

REPORT = """engine: 13.0.0
snapshot: 2026-10-20T05:32:17Z
checksum: sha256:{checksum}
project: demo
branch: main
notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.
score-policy: prefer-newest
threshold: 7
fail-on-kev: true
fail-unscored: false
private-suppressions: none
{provenance}direct:
production:
finding: CVE-2021-44228 cvss=3.1 score=10.0 source=NVD vector=CVSS:3.1/AV:N enrichment=present kev=yes dependency=log4j-core-2.14.1.jar package=log4j-core@2.14.1 relationship=direct scope=production
"""

ENGINE = {
    "dependencies": [
        {
            "fileName": "log4j-core-2.14.1.jar",
            "sha256": "a" * 64,
            "packages": [{"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
            "vulnerabilities": [{"name": "CVE-2021-44228", "source": "NVD", "cvssv3": {"baseScore": 10.0}}],
        }
    ]
}


class ProvenanceTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "history-provenance" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)

    def _scan(self, name: str, provenance: str) -> None:
        directory = self.root / name
        directory.mkdir(parents=True)
        (directory / "checkstead.txt").write_text(REPORT.format(checksum="b" * 64, provenance=provenance), encoding="utf-8")
        (directory / "dependency-check-report.json").write_text(json.dumps(ENGINE), encoding="utf-8")

    def test_signed_reports_expose_authenticity_kev_and_policy(self) -> None:
        self._scan("01-signed", "snapshot-authenticity: signed\nsnapshot-key: checkstead-2026-10\n")
        scan = history_payload(load_history(self.root))["scans"][0]
        self.assertEqual(scan["authenticity"], "signed")
        self.assertEqual(scan["signatureKey"], "checkstead-2026-10")
        self.assertEqual(scan["policy"], {"scorePolicy": "prefer-newest", "threshold": "7", "failOnKev": "true", "failUnscored": "false"})
        finding = scan["findings"][0]
        self.assertTrue(finding["kev"])
        self.assertEqual(finding["score"], "10.0")

    def test_older_reports_say_nothing_instead_of_guessing(self) -> None:
        self._scan("01-old", "")
        scan = history_payload(load_history(self.root))["scans"][0]
        self.assertIsNone(scan["authenticity"])
        self.assertIsNone(scan["signatureKey"])
        self.assertTrue(scan["findings"][0]["kev"])

    def test_the_scan_writes_provenance_into_the_report_header(self) -> None:
        source = (ROOT / "src" / "checkstead" / "scan.py").read_text(encoding="utf-8")
        self.assertIn('f"snapshot-authenticity: {snapshot.authenticity}"', source)
        self.assertIn("provenance,", source)
