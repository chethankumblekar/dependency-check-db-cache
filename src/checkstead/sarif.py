"""SARIF 2.1.0 for a Checkstead scan.

GitHub's Security tab reads this file. The result names the classification
and the score source. Nothing in this module contacts a vulnerability feed.
"""

from __future__ import annotations

import json
from pathlib import Path

from checkstead import __version__
from checkstead.score import FindingLine

SARIF_NAME = "checkstead.sarif"
_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def write_sarif(out_dir: Path, findings: list[FindingLine], project: str | None) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / SARIF_NAME
    path.write_text(json.dumps(_document(findings, project), indent=2) + "\n", encoding="utf-8")
    return path


def _document(findings: list[FindingLine], project: str | None) -> dict:
    rules = []
    seen: set[str] = set()
    results = []
    for finding in findings:
        if finding.identifier not in seen:
            seen.add(finding.identifier)
            summary = finding.description or finding.identifier
            rules.append(
                {
                    "id": finding.identifier,
                    "shortDescription": {"text": summary},
                    "fullDescription": {"text": summary},
                    "helpUri": "https://github.com/chethankumblekar/dependency-check-db-cache",
                }
            )
        results.append(_result(finding, project))
    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Checkstead",
                        "version": __version__,
                        "informationUri": "https://github.com/chethankumblekar/dependency-check-db-cache",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _result(finding: FindingLine, project: str | None) -> dict:
    source = finding.choice.source if finding.choice is not None else "none"
    score = f"{finding.choice.value:.1f}" if finding.choice is not None else "0.0"
    relationship = finding.relationship
    scope = finding.scope
    package = finding.package()
    text = (
        f"{finding.identifier} on {finding.dependency} "
        f"({relationship}, {scope}). "
        f"package {package}. "
        f"cvss {finding.choice.version if finding.choice else 'none'} "
        f"score {score if finding.choice else 'none'} source {source}"
    )
    if finding.description:
        text = f"{text}. {finding.description}"
    if project:
        text = f"{project}: {text}"
    return {
        "ruleId": finding.identifier,
        "level": _level(finding),
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location or finding.dependency},
                }
            }
        ],
        "properties": {
            "relationship": relationship,
            "scope": scope,
            "groups": [relationship, scope],
            "package": package,
            "description": finding.description,
            "scoreSource": source,
            "security-severity": score,
        },
    }


def _level(finding: FindingLine) -> str:
    if finding.choice is None:
        return "note"
    if finding.choice.value >= 7:
        return "error"
    if finding.choice.value >= 4:
        return "warning"
    return "note"
