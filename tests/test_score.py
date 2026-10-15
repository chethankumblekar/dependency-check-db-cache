"""Score policy and private suppressions. No vulnerability feed is contacted."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.config import DEFAULT_SNAPSHOT_URL, parse_config_text  # noqa: E402
from checkstead.errors import ChecksteadError  # noqa: E402
from checkstead.history import load_scan  # noqa: E402
from checkstead.roles import roles_from_paths  # noqa: E402
from checkstead.sarif import SARIF_NAME, write_sarif  # noqa: E402
from checkstead.score import evaluate_report  # noqa: E402
from checkstead.scan import build_scan_command  # noqa: E402
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

    def test_a_score_policy_file_uses_the_default_snapshot(self) -> None:
        only_policy = parse_config_text(
            "scorePolicy: highest\nthreshold: 7\n",
            Path("/Users/cipher_crawler/Playground/genesis/checkstead.yml"),
        )
        self.assertEqual(only_policy.snapshot_url, DEFAULT_SNAPSHOT_URL)
        self.assertEqual(only_policy.score_policy, "highest")
        self.assertEqual(only_policy.threshold, 7)
        blank = parse_config_text("snapshot:\nscorePolicy: prefer-newest\n")
        self.assertEqual(blank.snapshot_url, DEFAULT_SNAPSHOT_URL)
        explicit = "https://example.invalid/manifest.json"
        kept = parse_config_text(f"snapshot: {explicit}\nscorePolicy: highest\n")
        self.assertEqual(kept.snapshot_url, explicit)
        self.assertEqual(kept.score_policy, "highest")

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

    def test_private_suppressions_are_optional(self) -> None:
        root = ROOT / "build" / "tests" / "optional-suppressions"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        self.assertIsNone(resolve_private_suppressions(""))
        self.assertIsNone(resolve_private_suppressions("   "))
        self.assertIsNone(resolve_private_suppressions("missing-suppressions.xml", root))
        empty = root / "empty.xml"
        empty.write_text("\n", encoding="utf-8")
        self.assertIsNone(resolve_private_suppressions(str(empty)))
        shell = root / "shell.xml"
        shell.write_text(
            "<?xml version=\"1.0\"?><suppressions></suppressions>\n",
            encoding="utf-8",
        )
        self.assertIsNone(resolve_private_suppressions(str(shell)))
        rules = root / "rules.xml"
        rules.write_text(
            "<?xml version=\"1.0\"?>\n"
            "<suppressions><suppress><cve>CVE-2020-0001</cve></suppress></suppressions>\n",
            encoding="utf-8",
        )
        self.assertEqual(resolve_private_suppressions(str(rules)), rules)
        engine = Path("/opt/dependency-check/bin/dependency-check.sh")
        bare = build_scan_command(engine, Path("/var/cache"), [root], "sample", root / "out")
        self.assertNotIn("--suppression", bare)
        applied = build_scan_command(
            engine, Path("/var/cache"), [root], "sample", root / "out", suppressions=[rules]
        )
        self.assertIn("--suppression", applied)
        self.assertIn(str(rules), applied)

    def test_a_fuzzy_cpe_is_omitted_and_the_package_identity_is_kept(self) -> None:
        payload = {
            "dependencies": [
                {
                    "fileName": "next:16.3.5",
                    "filePath": "/work/node_modules/next/package.json",
                    "packages": [
                        {"id": "pkg:npm/next@16.3.5", "confidence": "HIGHEST"},
                        {
                            "id": "cpe:2.3:a:nextgen:nextgen:1.0:*:*:*:*:*:*:*",
                            "confidence": "LOW",
                            "notes": "fuzzy match",
                        },
                    ],
                    "vulnerabilityIds": [
                        {
                            "id": "cpe:2.3:a:nextgen:nextgen:1.0:*:*:*:*:*:*:*",
                            "confidence": "LOW",
                            "notes": "fuzzy match",
                        }
                    ],
                    "vulnerabilities": [
                        _vuln("CVE-FUZZY", "NVD", _v3(9.8)),
                        {"name": "GHSA-next", "source": "NPM", **_v3(5.3)},
                    ],
                },
                {
                    "fileName": "braces:3.0.2",
                    "packages": [{"id": "pkg:npm/braces@3.0.2", "confidence": "HIGHEST"}],
                    "vulnerabilityIds": [
                        {"id": "cpe:2.3:a:braces:braces:3.0.2:*:*:*:*:*:*:*", "confidence": "HIGHEST"}
                    ],
                    "vulnerabilities": [
                        {
                            "name": "CVE-REAL",
                            "source": "NVD",
                            **_v3(7.5),
                            "vulnerableSoftware": [
                                {"software": {"id": "cpe:2.3:a:braces:braces:3.0.2:*:*:*:*:*:*:*"}}
                            ],
                        }
                    ],
                },
            ]
        }
        root = ROOT / "build" / "tests" / "npm-roles"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        (root / "package.json").write_text(
            json.dumps({"dependencies": {"next": "16.3.5"}, "devDependencies": {"eslint": "9.0.0"}}),
            encoding="utf-8",
        )
        (root / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "": {},
                        "node_modules/next": {"version": "16.3.5"},
                        "node_modules/braces": {"version": "3.0.2", "dev": True},
                        "node_modules/@modelcontextprotocol/sdk": {"version": "1.0.0", "dev": True},
                    }
                }
            ),
            encoding="utf-8",
        )
        roles = roles_from_paths([root])
        result = evaluate_report(
            payload,
            policy="prefer-newest",
            threshold=None,
            fail_on_kev=False,
            fail_unscored=False,
            roles=roles,
        )
        joined = "\n".join(result.lines)
        self.assertNotIn("CVE-FUZZY", joined)
        self.assertIn("GHSA-next", joined)
        self.assertIn("relationship=direct scope=production", joined)
        self.assertIn("CVE-REAL", joined)
        self.assertIn("dependency=braces:3.0.2", joined)
        self.assertIn("relationship=transitive scope=dev", joined)
        self.assertNotIn("services.nvd.nist.gov", joined)
        braces = next(item for item in result.findings if item.identifier == "CVE-REAL")
        self.assertEqual(braces.scope, "dev")
        self.assertNotEqual(braces.scope, "production")
        nxt = next(item for item in result.findings if item.identifier == "GHSA-next")
        self.assertEqual((nxt.relationship, nxt.scope), ("direct", "production"))
        self.assertEqual(nxt.choice.source, "NPM")
        sarif_path = write_sarif(root / "out", result.findings, "next-app")
        self.assertEqual(sarif_path.name, SARIF_NAME)
        document = json.loads(sarif_path.read_text(encoding="utf-8"))
        results = document["runs"][0]["results"]
        self.assertEqual({item["ruleId"] for item in results}, {"GHSA-next", "CVE-REAL"})
        real = next(item for item in results if item["ruleId"] == "CVE-REAL")
        self.assertEqual(real["properties"]["relationship"], "transitive")
        self.assertEqual(real["properties"]["scope"], "dev")
        self.assertEqual(real["properties"]["scoreSource"], "NVD")
        self.assertEqual(real["properties"]["security-severity"], "7.5")
        self.assertIn("transitive, dev", real["message"]["text"])
        self.assertIn("source NVD", real["message"]["text"])
        self.assertNotIn("CVE-FUZZY", sarif_path.read_text(encoding="utf-8"))

        report = root / "out"
        (report / "checkstead.txt").write_text(
            "engine: 13.0.0\n"
            "snapshot: 2026-10-06T01:02:03Z\n"
            "checksum: sha256:abc\n"
            "project: next-app\n"
            "notice: This product uses data from the NVD API but is not endorsed or certified by the NVD.\n"
            + joined
            + "\n",
            encoding="utf-8",
        )
        (report / "dependency-check-report.json").write_text(json.dumps(payload), encoding="utf-8")
        scan = load_scan(report)
        identifiers = {item.identifier for item in scan.findings}
        self.assertNotIn("CVE-FUZZY", identifiers)
        real_finding = next(item for item in scan.findings if item.identifier == "CVE-REAL")
        self.assertEqual(real_finding.relationship, "transitive")
        self.assertEqual(real_finding.scope, "dev")
        self.assertEqual(real_finding.score_source, "NVD")
        dev_finding = next(item for item in scan.findings if item.identifier == "GHSA-next")
        self.assertEqual(dev_finding.scope, "production")
        self.assertNotEqual(dev_finding.scope, real_finding.scope)
