"""Named score policies over a Dependency-Check JSON report.

The numbers come from that report. This module does not fetch a vulnerability feed.
"""

from __future__ import annotations

from dataclasses import dataclass

from checkstead.errors import ChecksteadError
from checkstead.match import confirmed_vulnerability, ecosystem_identity

POLICIES = ("prefer-newest", "highest")
POLICY_FAILURE = 3
_ANALYZERS = {"NVD", "OSSINDEX", "NPM", "RETIREJS", "CISA"}

_V3_PARTS = (
    ("AV", "attackVector", {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}),
    ("AC", "attackComplexity", {"LOW": "L", "HIGH": "H"}),
    ("PR", "privilegesRequired", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
    ("UI", "userInteraction", {"NONE": "N", "REQUIRED": "R"}),
    ("S", "scope", {"UNCHANGED": "U", "CHANGED": "C"}),
    ("C", "confidentialityImpact", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
    ("I", "integrityImpact", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
    ("A", "availabilityImpact", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
)
_V2_PARTS = (
    ("AV", "accessVector", {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L"}),
    ("AC", "accessComplexity", {"HIGH": "H", "MEDIUM": "M", "LOW": "L"}),
    ("Au", "authentication", {"NONE": "N", "SINGLE": "S", "MULTIPLE": "M"}),
    ("C", "confidentialityImpact", {"NONE": "N", "PARTIAL": "P", "COMPLETE": "C"}),
    ("I", "integrityImpact", {"NONE": "N", "PARTIAL": "P", "COMPLETE": "C"}),
    ("A", "availabilityImpact", {"NONE": "N", "PARTIAL": "P", "COMPLETE": "C"}),
)


@dataclass(frozen=True)
class ScoreChoice:
    version: str
    major: int
    value: float
    vector: str
    source: str
    kind: str


@dataclass(frozen=True)
class FindingLine:
    dependency: str
    identifier: str
    choice: ScoreChoice | None
    kev: bool
    enrichment: str
    relationship: str = "direct"
    scope: str = "production"
    location: str = ""

    def report(self) -> str:
        if self.choice is None:
            version, score, vector, source = "none", "none", "none", "none"
        else:
            version = self.choice.version
            score = _number(self.choice.value)
            vector = self.choice.vector or "none"
            source = self.choice.source or "none"
        kev = "yes" if self.kev else "no"
        return (
            f"finding: {self.identifier} cvss={version} score={score} "
            f"source={source} vector={vector} enrichment={self.enrichment} "
            f"kev={kev} dependency={self.dependency} "
            f"relationship={self.relationship} scope={self.scope}"
        )

    def failure(self, policy: str, reason: str) -> str:
        if reason == "score" and self.choice is not None:
            return (
                f"{policy} failed the build on {self.identifier} "
                f"cvss {self.choice.version} score {_number(self.choice.value)} "
                f"source {self.choice.source}"
            )
        if reason == "kev":
            return f"{policy} failed the build on {self.identifier} kev"
        return f"{policy} failed the build on {self.identifier} no score"


@dataclass(frozen=True)
class ScoreResult:
    lines: list[str]
    failures: list[str]
    findings: list[FindingLine]


def _number(value: float) -> str:
    text = f"{value:.1f}"
    return text


def _classify(source: str) -> str:
    text = source.strip()
    if not text:
        return "other"
    if text.upper() == "NVD" or "nist.gov" in text.lower():
        return "nvd"
    if "@" in text:
        return "cna"
    if text.upper() in _ANALYZERS:
        return "other"
    return "cna"


def _vector(parts: tuple[tuple[str, str, dict[str, str]], ...], block: dict, prefix: str) -> str:
    encoded: list[str] = []
    for label, key, mapping in parts:
        raw = block.get(key)
        if key == "authentication" and raw is None:
            raw = block.get("authenticationr")
        if not isinstance(raw, str):
            return "none"
        code = mapping.get(raw.strip().upper())
        if code is None:
            return "none"
        encoded.append(f"{label}:{code}")
    return prefix + "/".join(encoded)


def _score_from_block(block: dict, major: int, vuln_source: str) -> ScoreChoice | None:
    raw = block.get("baseScore")
    if raw is None:
        raw = block.get("score")
    if isinstance(raw, str):
        try:
            raw = float(raw)
        except ValueError:
            return None
    if not isinstance(raw, (int, float)):
        return None
    version = block.get("version")
    version_text = str(version).strip() if version else str(major)
    metric_source = block.get("source")
    source = str(metric_source).strip() if isinstance(metric_source, str) and metric_source.strip() else vuln_source
    if major == 4 and isinstance(block.get("vectorString"), str) and block["vectorString"].strip():
        vector = block["vectorString"].strip()
    elif major == 3:
        prefix = "CVSS:3.1/" if version_text.startswith("3.1") else "CVSS:3.0/"
        vector = _vector(_V3_PARTS, block, prefix)
    elif major == 2:
        vector = _vector(_V2_PARTS, block, "")
    else:
        vector = "none"
    return ScoreChoice(version_text, major, float(raw), vector, source, _classify(source))


def _scores(vulnerability: dict) -> list[ScoreChoice]:
    source = vulnerability.get("source")
    vuln_source = source.strip() if isinstance(source, str) else ""
    found: list[ScoreChoice] = []
    for major, key in ((2, "cvssv2"), (3, "cvssv3"), (4, "cvssv4")):
        block = vulnerability.get(key)
        if not isinstance(block, dict):
            continue
        choice = _score_from_block(block, major, vuln_source)
        if choice is not None:
            found.append(choice)
    return found


def _has_cpe(dependency: dict, vulnerability: dict) -> bool:
    for block in vulnerability.get("vulnerableSoftware") or []:
        if isinstance(block, dict):
            software = block.get("software")
            if isinstance(software, dict) and str(software.get("id", "")).startswith("cpe:"):
                return True
    for block in dependency.get("vulnerabilityIds") or []:
        if isinstance(block, dict) and str(block.get("id", "")).startswith("cpe:"):
            return True
    return False


def _choose(scores: list[ScoreChoice], policy: str) -> ScoreChoice | None:
    if not scores:
        return None
    if policy == "highest":
        return max(scores, key=lambda item: (item.value, item.major, item.source))
    nvd = [item for item in scores if item.kind == "nvd"]
    cna = [item for item in scores if item.kind == "cna"]
    pool = nvd or cna or scores
    return max(pool, key=lambda item: (item.major, item.value, item.source))


def _enrichment(has_cpe: bool, has_nvd_score: bool) -> str:
    if has_cpe and has_nvd_score:
        return "present"
    if not has_cpe and not has_nvd_score:
        return "no-cpe-no-nvd-score"
    if not has_cpe:
        return "no-cpe"
    return "no-nvd-score"


def findings_from_report(payload: dict, policy: str, roles=None) -> list[FindingLine]:
    if policy not in POLICIES:
        raise ChecksteadError(f"scorePolicy must be prefer-newest or highest, not {policy!r}.")
    grouped: dict[tuple[str, str], list[dict]] = {}
    cpe: dict[tuple[str, str], bool] = {}
    deps: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    for dependency in payload.get("dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        name = str(dependency.get("fileName") or dependency.get("name") or "dependency")
        for vulnerability in dependency.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            if not confirmed_vulnerability(dependency, vulnerability):
                continue
            identifier = str(vulnerability.get("name") or vulnerability.get("id") or "").strip()
            if not identifier:
                continue
            key = (name, identifier)
            if key not in grouped:
                grouped[key] = []
                cpe[key] = False
                deps[key] = dependency
                order.append(key)
            grouped[key].append(vulnerability)
            cpe[key] = cpe[key] or _has_cpe(dependency, vulnerability)
    lines: list[FindingLine] = []
    for key in order:
        records = grouped[key]
        scores = [score for record in records for score in _scores(record)]
        choice = _choose(scores, policy)
        kev = any(isinstance(record.get("knownExploitedVulnerability"), dict) for record in records)
        has_nvd = any(score.kind == "nvd" for score in scores)
        relationship, scope = _role_for(deps[key], roles)
        lines.append(
            FindingLine(
                key[0],
                key[1],
                choice,
                kev,
                _enrichment(cpe[key], has_nvd),
                relationship,
                scope,
                _location(deps[key]),
            )
        )
    return lines


def _role_for(dependency: dict, roles) -> tuple[str, str]:
    if roles is None or roles.empty:
        return "direct", "production"
    identity = ecosystem_identity(dependency)
    if identity is None:
        return "direct", "production"
    return roles.lookup(identity[0], identity[1])


def _location(dependency: dict) -> str:
    raw = str(dependency.get("filePath") or dependency.get("fileName") or "dependency")
    text = raw.replace("\\", "/")
    marker = "/work/"
    if marker in text:
        text = text.split(marker, 1)[1]
    if text.startswith("/"):
        text = text.rsplit("/", 1)[-1]
    return text or "dependency"


def evaluate_report(
    payload: dict,
    *,
    policy: str,
    threshold: float | None,
    fail_on_kev: bool,
    fail_unscored: bool,
    roles=None,
) -> ScoreResult:
    findings = findings_from_report(payload, policy, roles)
    failures: list[str] = []
    for finding in findings:
        if finding.choice is not None and threshold is not None and finding.choice.value >= threshold:
            failures.append(finding.failure(policy, "score"))
        if finding.kev and fail_on_kev:
            failures.append(finding.failure(policy, "kev"))
        if finding.choice is None and fail_unscored:
            failures.append(finding.failure(policy, "no-score"))
    report = [finding.report() for finding in findings]
    if not report:
        report = ["findings: none"]
    return ScoreResult(report, failures, findings)


