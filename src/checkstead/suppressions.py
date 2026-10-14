"""Private suppression files stay on disk. A URL is refused."""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree
from datetime import date
from pathlib import Path

from checkstead.errors import ChecksteadError


def public_suppression_file() -> Path | None:
    """The Checkstead public file, when it contains a rule.

    The shipped file has no rules. A rule is added only after a false match
    is confirmed. This function does not invent one.
    """
    path = Path(__file__).with_name("checkstead-public.xml")
    if not path.is_file():
        return None
    try:
        root = ElementTree.fromstring(path.read_text(encoding="utf-8"))
    except ElementTree.ParseError as exc:
        raise ChecksteadError(f"Public suppression file is not XML: {path}") from exc
    if any(_local(element.tag) == "suppress" for element in root.iter()):
        return path
    return None


def resolve_private_suppressions(value: str, base: Path | None = None) -> Path | None:
    text = value.strip()
    if not text:
        return None
    lowered = text.lower()
    if lowered.startswith(("http://", "https://", "file:")):
        raise ChecksteadError(
            "privateSuppressions must be a local file. A URL is not accepted."
        )
    path = Path(text)
    if not path.is_absolute():
        path = (base or Path.cwd()) / path
    if not path.is_file():
        raise ChecksteadError(f"Private suppression file not found: {path}")
    return path


def suppression_report(path: Path, today: date, seen_identifiers: set[str]) -> list[str]:
    """Expired rules and CVE rules that matched nothing in this report."""
    try:
        root = ElementTree.fromstring(path.read_text(encoding="utf-8"))
    except ElementTree.ParseError as exc:
        raise ChecksteadError(f"Private suppression file is not XML: {path}") from exc
    lines: list[str] = []
    for element in root.iter():
        if _local(element.tag) != "suppress":
            continue
        cve = ""
        for child in list(element):
            if _local(child.tag) == "cve" and child.text:
                cve = child.text.strip()
                break
        until = (element.attrib.get("until") or "").strip()
        label = cve or "rule"
        if until:
            try:
                expiry = date.fromisoformat(until[:10])
            except ValueError as exc:
                raise ChecksteadError(
                    f"Suppression until date is not YYYY-MM-DD: {until}"
                ) from exc
            if expiry < today:
                lines.append(f"suppression-expired: {label} until {until}")
        if cve and cve not in seen_identifiers:
            lines.append(f"suppression-unused: {cve}")
    return lines


def seen_identifiers(payload: dict) -> set[str]:
    found: set[str] = set()
    for dependency in payload.get("dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        for key in ("vulnerabilities", "suppressedVulnerabilities"):
            for vulnerability in dependency.get(key) or []:
                if isinstance(vulnerability, dict):
                    name = vulnerability.get("name") or vulnerability.get("id")
                    if isinstance(name, str) and name.strip():
                        found.add(name.strip())
    return found


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag
