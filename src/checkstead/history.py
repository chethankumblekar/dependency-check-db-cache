"""Read phase 1 scan reports and the drift between them.

Dependency and finding fields are taken from the engine report when it is
present. Score source is reported only when a finding actually carries one.
Suppressions and false positives are not invented.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from checkstead.engine import NVD_NOTICE


@dataclass(frozen=True)
class Dependency:
    key: str
    name: str
    version: str | None
    file_name: str
    sha256: str | None


@dataclass(frozen=True)
class Finding:
    dependency: str
    identifier: str
    cvss: dict[str, str]
    score_source: str | None
    score_source_present: bool


@dataclass
class Scan:
    id: str
    project: str | None
    engine: str
    snapshot: str
    checksum: str
    revision: str | None
    author: str | None
    author_email: str | None
    notice: str
    dependencies: list[Dependency]
    findings: list[Finding]
    has_dependency_report: bool
    has_score_source: bool


@dataclass
class Drift:
    before: str
    after: str
    dependencies_added: list[Dependency] = field(default_factory=list)
    dependencies_removed: list[Dependency] = field(default_factory=list)
    dependencies_changed: list[tuple[Dependency, Dependency]] = field(default_factory=list)
    findings_added: list[Finding] = field(default_factory=list)
    findings_removed: list[Finding] = field(default_factory=list)
    findings_changed: list[tuple[Finding, Finding]] = field(default_factory=list)
    score_source_available: bool = False


def parse_header(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def _cvss_scores(vulnerability: dict) -> dict[str, str]:
    scores: dict[str, str] = {}
    for version, key in (("2", "cvssv2"), ("3", "cvssv3"), ("4", "cvssv4")):
        block = vulnerability.get(key)
        if not isinstance(block, dict):
            continue
        raw = block.get("baseScore")
        if raw is None and isinstance(block.get("cvssData"), dict):
            raw = block["cvssData"].get("baseScore")
        if raw is not None and raw != "":
            scores[version] = str(raw)
    return scores


def _finding(dependency_name: str, vulnerability: dict) -> Finding:
    if "scoreSource" in vulnerability:
        present = True
        source = vulnerability.get("scoreSource")
    elif "source" in vulnerability:
        present = True
        source = vulnerability.get("source")
    else:
        present = False
        source = None
    source_text = source.strip() if isinstance(source, str) and source.strip() else None
    return Finding(
        dependency=dependency_name,
        identifier=str(vulnerability.get("name") or vulnerability.get("id") or ""),
        cvss=_cvss_scores(vulnerability),
        score_source=source_text,
        score_source_present=present,
    )


def _dependency(raw: dict) -> Dependency:
    name = raw.get("name") or raw.get("fileName") or ""
    version = raw.get("version") or None
    file_name = raw.get("fileName") or name
    sha = raw.get("sha256") or None
    key = name or file_name
    return Dependency(
        key=str(key),
        name=str(name or file_name),
        version=str(version) if version else None,
        file_name=str(file_name),
        sha256=str(sha) if sha else None,
    )


def load_engine_report(path: Path) -> tuple[list[Dependency], list[Finding], bool]:
    """Return dependencies, findings, and whether any finding has a score source."""
    if not path.is_file():
        return [], [], False
    payload = json.loads(path.read_text(encoding="utf-8"))
    dependencies: list[Dependency] = []
    findings: list[Finding] = []
    has_score_source = False
    for raw in payload.get("dependencies") or []:
        if not isinstance(raw, dict):
            continue
        dependency = _dependency(raw)
        dependencies.append(dependency)
        for vulnerability in raw.get("vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            finding = _finding(dependency.name, vulnerability)
            findings.append(finding)
            has_score_source = has_score_source or finding.score_source_present
    dependencies.sort(key=lambda item: item.name)
    findings.sort(key=lambda item: (item.dependency, item.identifier))
    return dependencies, findings, has_score_source


def load_scan(directory: Path) -> Scan:
    header = parse_header((directory / "checkstead.txt").read_text(encoding="utf-8"))
    report = directory / "dependency-check-report.json"
    dependencies, findings, has_score_source = load_engine_report(report)
    return Scan(
        id=directory.name,
        project=header.get("project") or None,
        engine=header.get("engine", ""),
        snapshot=header.get("snapshot", ""),
        checksum=header.get("checksum", ""),
        revision=header.get("revision") or None,
        author=header.get("author") or None,
        author_email=header.get("author-email") or None,
        notice=header.get("notice", NVD_NOTICE),
        dependencies=dependencies,
        findings=findings,
        has_dependency_report=report.is_file(),
        has_score_source=has_score_source,
    )


def load_history(root: Path) -> list[Scan]:
    scans = [
        load_scan(path)
        for path in sorted(path for path in root.iterdir() if path.is_dir())
        if (path / "checkstead.txt").is_file()
    ]
    return scans


def _same_dependency(left: Dependency, right: Dependency) -> bool:
    return left.version == right.version and left.sha256 == right.sha256 and left.file_name == right.file_name


def _same_finding(left: Finding, right: Finding) -> bool:
    return left.cvss == right.cvss and left.score_source == right.score_source


def diff_scans(before: Scan, after: Scan) -> Drift:
    drift = Drift(before=before.id, after=after.id)
    previous = {item.key: item for item in before.dependencies}
    current = {item.key: item for item in after.dependencies}
    for key in sorted(set(previous) | set(current)):
        old = previous.get(key)
        new = current.get(key)
        if old is None and new is not None:
            drift.dependencies_added.append(new)
        elif new is None and old is not None:
            drift.dependencies_removed.append(old)
        elif old is not None and new is not None and not _same_dependency(old, new):
            drift.dependencies_changed.append((old, new))

    def finding_key(item: Finding) -> tuple[str, str]:
        return (item.dependency, item.identifier)

    previous_findings = {finding_key(item): item for item in before.findings}
    current_findings = {finding_key(item): item for item in after.findings}
    for key in sorted(set(previous_findings) | set(current_findings)):
        old = previous_findings.get(key)
        new = current_findings.get(key)
        if old is None and new is not None:
            drift.findings_added.append(new)
        elif new is None and old is not None:
            drift.findings_removed.append(old)
        elif old is not None and new is not None and not _same_finding(old, new):
            drift.findings_changed.append((old, new))
    drift.score_source_available = before.has_score_source or after.has_score_source
    return drift


def _dependency_json(item: Dependency) -> dict:
    return {
        "name": item.name,
        "version": item.version,
        "fileName": item.file_name,
        "sha256": item.sha256,
    }


def _finding_json(item: Finding) -> dict:
    payload = {
        "dependency": item.dependency,
        "id": item.identifier,
        "cvss": item.cvss,
    }
    if item.score_source_present:
        payload["scoreSource"] = item.score_source
    return payload


def history_payload(scans: list[Scan]) -> dict:
    drifts = [diff_scans(scans[index - 1], scans[index]) for index in range(1, len(scans))]
    return {
        "notice": scans[0].notice if scans else NVD_NOTICE,
        "scans": [
            {
                "id": scan.id,
                "project": scan.project,
                "engine": scan.engine,
                "snapshot": scan.snapshot,
                "checksum": scan.checksum,
                "revision": scan.revision,
                "author": scan.author,
                "authorEmail": scan.author_email,
                "hasDependencyReport": scan.has_dependency_report,
                "hasScoreSource": scan.has_score_source,
                "dependencies": [_dependency_json(item) for item in scan.dependencies],
                "findings": [_finding_json(item) for item in scan.findings],
            }
            for scan in scans
        ],
        "drifts": [
            {
                "before": drift.before,
                "after": drift.after,
                "dependencies": {
                    "added": [_dependency_json(item) for item in drift.dependencies_added],
                    "removed": [_dependency_json(item) for item in drift.dependencies_removed],
                    "changed": [
                        {"before": _dependency_json(old), "after": _dependency_json(new)}
                        for old, new in drift.dependencies_changed
                    ],
                },
                "findings": {
                    "added": [_finding_json(item) for item in drift.findings_added],
                    "removed": [_finding_json(item) for item in drift.findings_removed],
                    "changed": [
                        {"before": _finding_json(old), "after": _finding_json(new)}
                        for old, new in drift.findings_changed
                    ],
                },
                "scores": {"available": drift.score_source_available},
            }
            for drift in drifts
        ],
        "later": {"suppressions": [], "falsePositives": []},
    }
