"""CPE confirmation must not drop real findings for Java and other namespaced packages.

These shapes are copied from a Dependency-Check 13.0.0 report produced on
20 October 2026 against the published snapshot. Before the fix, Checkstead
omitted CVE-2015-6420 for commons-collections 3.2.1, a Critical finding the
engine reported with a HIGHEST-confidence CPE.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.match import confirmed_vulnerability  # noqa: E402
from checkstead.score import evaluate_report  # noqa: E402


def _dependency(file_name: str, purl: str, cpe: str, confidence: str = "HIGHEST", notes: str = "") -> dict:
    identifier = {"id": cpe, "confidence": confidence}
    if notes:
        identifier["notes"] = notes
    return {
        "fileName": file_name,
        "packages": [{"id": purl, "confidence": "HIGH"}],
        "vulnerabilityIds": [identifier],
    }


def _nvd(name: str, *cpes: str) -> dict:
    return {
        "name": name,
        "source": "NVD",
        "severity": "CRITICAL",
        "cvssv3": {
            "baseScore": 9.8,
            "version": "3.1",
            "attackVector": "NETWORK",
            "attackComplexity": "LOW",
            "privilegesRequired": "NONE",
            "userInteraction": "NONE",
            "scope": "UNCHANGED",
            "confidentialityImpact": "HIGH",
            "integrityImpact": "HIGH",
            "availabilityImpact": "HIGH",
        },
        "vulnerableSoftware": [{"software": {"id": cpe}} for cpe in cpes],
    }


COMMONS = _dependency(
    "commons-collections-3.2.1.jar",
    "pkg:maven/commons-collections/commons-collections@3.2.1",
    "cpe:2.3:a:apache:commons_collections:3.2.1:*:*:*:*:*:*:*",
)
COMMONS_CVE = _nvd(
    "CVE-2015-6420",
    "cpe:2.3:a:apache:commons_collections:*:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:commons_collections:4.0:*:*:*:*:*:*:*",
)
LOG4J = _dependency(
    "log4j-core-2.14.1.jar",
    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
)
LOG4SHELL = _nvd("CVE-2021-44228", "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")


class JavaFindingsAreKept(TestCase):
    def test_commons_collections_critical_is_confirmed(self) -> None:
        self.assertTrue(confirmed_vulnerability(COMMONS, COMMONS_CVE))

    def test_log4shell_is_confirmed(self) -> None:
        self.assertTrue(confirmed_vulnerability(LOG4J, LOG4SHELL))

    def test_a_go_module_path_is_confirmed(self) -> None:
        dependency = _dependency(
            "golang.org/x/net:0.7.0",
            "pkg:golang/golang.org/x/net@0.7.0",
            "cpe:2.3:a:golang:networking:0.7.0:*:*:*:*:*:*:*",
        )
        self.assertTrue(
            confirmed_vulnerability(dependency, _nvd("CVE-2023-39325", "cpe:2.3:a:golang:networking:*:*:*:*:*:*:*:*"))
        )

    def test_the_report_lists_the_finding_and_can_fail_the_build(self) -> None:
        payload = {"dependencies": [dict(COMMONS, vulnerabilities=[COMMONS_CVE]), dict(LOG4J, vulnerabilities=[LOG4SHELL])]}
        result = evaluate_report(payload, policy="prefer-newest", threshold=7.0, fail_on_kev=False, fail_unscored=False)
        joined = "\n".join(result.lines)
        self.assertIn("CVE-2015-6420", joined)
        self.assertIn("CVE-2021-44228", joined)
        self.assertTrue(result.failures)


class FalsePositivesStayOut(TestCase):
    def test_a_fuzzy_low_confidence_cpe_is_still_dropped(self) -> None:
        dependency = _dependency(
            "next:16.3.5",
            "pkg:npm/next@16.3.5",
            "cpe:2.3:a:nextgen:nextgen:1.0:*:*:*:*:*:*:*",
            confidence="LOW",
            notes="fuzzy match",
        )
        self.assertFalse(
            confirmed_vulnerability(dependency, _nvd("CVE-FUZZY", "cpe:2.3:a:nextgen:nextgen:1.0:*:*:*:*:*:*:*"))
        )

    def test_a_vulnerability_for_another_product_is_dropped(self) -> None:
        # The engine attached a CVE whose CPEs name a different product than
        # the one it identified this jar as.
        self.assertFalse(
            confirmed_vulnerability(COMMONS, _nvd("CVE-OTHER", "cpe:2.3:a:apache:commons_text:*:*:*:*:*:*:*:*"))
        )

    def test_a_medium_cpe_that_names_another_package_is_dropped(self) -> None:
        dependency = _dependency(
            "braces:3.0.2",
            "pkg:npm/braces@3.0.2",
            "cpe:2.3:a:brace_project:brace:3.0.2:*:*:*:*:*:*:*",
            confidence="MEDIUM",
        )
        self.assertFalse(
            confirmed_vulnerability(dependency, _nvd("CVE-BRACE", "cpe:2.3:a:brace_project:brace:*:*:*:*:*:*:*:*"))
        )

    def test_a_cpe_for_a_different_version_is_dropped(self) -> None:
        self.assertFalse(
            confirmed_vulnerability(COMMONS, _nvd("CVE-V4", "cpe:2.3:a:apache:commons_collections:4.0:*:*:*:*:*:*:*"))
        )
