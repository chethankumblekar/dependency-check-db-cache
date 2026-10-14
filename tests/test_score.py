"""Score policy and private suppressions. No vulnerability feed is contacted."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.config import parse_config_text  # noqa: E402
from checkstead.errors import ChecksteadError  # noqa: E402
from checkstead.score import evaluate_report  # noqa: E402
from checkstead.suppressions import public_suppression_file, resolve_private_suppressions  # noqa: E402


def _vuln(name: str, source: str, scores: dict, kev: bool = False, cpe: bool = True) -> dict:
    vulnerability: dict = {"name": name, "source": source}
    vulnerability.update(scores)
    if kev:
        vulnerability["knownExploitedVulnerability"] = {"Name": name}
    if cpe:
        vulnerability["vulnerableSoftware"] = [{"software": {"id": "cpe:2.3:a:example:example:*:*:*:*:*:*:*:*"}}]
    return vulnerability


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


def _report(*vulnerabilities: dict) -> dict:
    return {"dependencies": [{"fileName": "example.jar", "vulnerabilities": list(vulnerabilities)}]}


class ScoreTests(TestCase):
    def test_prefer_newest_keeps_the_nvd_score(self) -> None:
        payload = _report(
            _vuln("CVE-2021-44228", "NVD", _v3(7.5)),
            _vuln("CVE-2021-44228", "OSSINDEX", {"cvssv2": {"score": 10.0, "version": "2.0"}}),
        )
        result = evaluate_report(
            payload, policy="prefer-newest", threshold=9, fail_on_kev=False, fail_unscored=False
        )
        self.assertEqual(result.failures, [])
        self.assertIn("cvss=3.1 score=7.5 source=NVD", result.lines[0])
        self.assertIn("enrichment=present", result.lines[0])
        self.assertIn("kev=no", result.lines[0])
        self.assertIn("vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", result.lines[0])

    def test_highest_uses_the_larger_score_from_any_source(self) -> None:
        payload = _report(
            _vuln("CVE-2021-44228", "NVD", _v3(7.5)),
            _vuln("CVE-2021-44228", "OSSINDEX", _v3(10.0)),
        )
        result = evaluate_report(
            payload, policy="highest", threshold=9, fail_on_kev=False, fail_unscored=False
        )
        self.assertEqual(
            result.failures,
            ["highest failed the build on CVE-2021-44228 cvss 3.1 score 10.0 source OSSINDEX"],
        )

    def test_a_cna_score_is_used_when_nvd_published_none(self) -> None:
        payload = _report(
            _vuln("CVE-2024-1000", "NVD", _v3(6.5, "cna@example.com"), cpe=False),
        )
        result = evaluate_report(
            payload, policy="prefer-newest", threshold=None, fail_on_kev=False, fail_unscored=False
        )
        self.assertIn("score=6.5 source=cna@example.com", result.lines[0])
        self.assertIn("enrichment=no-cpe-no-nvd-score", result.lines[0])
        self.assertEqual(result.failures, [])

    def test_kev_below_the_threshold_stays_a_finding(self) -> None:
        payload = _report(_vuln("CVE-2021-44228", "NVD", _v3(4.0), kev=True))
        quiet = evaluate_report(
            payload, policy="prefer-newest", threshold=9, fail_on_kev=False, fail_unscored=False
        )
        self.assertEqual(quiet.failures, [])
        self.assertIn("kev=yes", quiet.lines[0])
        failing = evaluate_report(
            payload, policy="prefer-newest", threshold=9, fail_on_kev=True, fail_unscored=False
        )
        self.assertEqual(
            failing.failures,
            ["prefer-newest failed the build on CVE-2021-44228 kev"],
        )

    def test_no_score_is_visible_and_fails_only_when_asked(self) -> None:
        payload = _report(_vuln("CVE-2024-2000", "NVD", {}, cpe=False))
        shown = evaluate_report(
            payload, policy="prefer-newest", threshold=0, fail_on_kev=False, fail_unscored=False
        )
        self.assertIn("score=none", shown.lines[0])
        self.assertEqual(shown.failures, [])
        failing = evaluate_report(
            payload, policy="prefer-newest", threshold=0, fail_on_kev=False, fail_unscored=True
        )
        self.assertEqual(
            failing.failures,
            ["prefer-newest failed the build on CVE-2024-2000 no score"],
        )

    def test_config_names_the_two_policies_and_refuses_a_url(self) -> None:
        parsed = parse_config_text(
            "snapshot: https://example.invalid/manifest.json\nscorePolicy:\nthreshold:\n",
        )
        self.assertEqual(parsed.score_policy, "prefer-newest")
        self.assertIsNone(parsed.threshold)
        with self.assertRaises(ChecksteadError):
            parse_config_text("snapshot: https://example.invalid/manifest.json\nscorePolicy: any\n")
        with self.assertRaises(ChecksteadError):
            resolve_private_suppressions("https://example.invalid/suppress.xml")
        self.assertIsNone(public_suppression_file())

    def test_a_private_file_must_exist(self) -> None:
        with self.assertRaises(ChecksteadError):
            resolve_private_suppressions("missing-suppressions.xml", Path("/tmp"))
