"""Which Dependency-Check vulnerabilities are confirmed findings.

A package URL, or a name and version from the ecosystem, is the identity.
A CPE match is confirmed only when it names that same package. Dependency-Check
records a fuzzy CPE match at low confidence. Those are not confirmed findings.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

_VERSION = re.compile(r"^\d")


def ecosystem_identity(dependency: dict) -> tuple[str, str] | None:
    """Package name and version from a package URL, or from name and version."""
    best: tuple[str, str] | None = None
    best_rank = -1
    for block in dependency.get("packages") or []:
        if not isinstance(block, dict):
            continue
        parsed = _purl(str(block.get("id") or ""))
        if parsed is None:
            continue
        rank = _confidence_rank(str(block.get("confidence") or ""))
        if rank >= best_rank:
            best = parsed
            best_rank = rank
    if best is not None:
        return best
    name = dependency.get("name")
    version = dependency.get("version")
    if isinstance(name, str) and name.strip() and isinstance(version, str) and _VERSION.match(version.strip()):
        return name.strip(), version.strip()
    file_name = str(dependency.get("fileName") or "")
    return _name_version(file_name)


def confirmed_vulnerability(dependency: dict, vulnerability: dict) -> bool:
    """False when the only link is a fuzzy CPE, or a CPE for a different package."""
    source = str(vulnerability.get("source") or "").strip().upper()
    if source and source != "NVD":
        return True
    return _nvd_matches(dependency, vulnerability)


def _nvd_matches(dependency: dict, vulnerability: dict) -> bool:
    """Whether an NVD record really belongs to this dependency.

    Dependency-Check identifies a dependency by CPE and records how sure it
    is. A HIGH or HIGHEST identification is the engine's evidence and is
    trusted as is; a CPE vendor and product often differ from a Maven group
    and artifact (apache:log4j for org.apache.logging.log4j/log4j-core), so a
    name comparison would drop real findings such as Log4Shell. A MEDIUM
    identification counts only when it names the package. LOW or fuzzy alone
    is never enough. The record's own CPEs then have to name the same vendor,
    product, and version as a trusted identification.
    """
    identity = ecosystem_identity(dependency)
    identifiers = _cpe_identifiers(dependency)
    vuln_cpes = _vulnerability_cpes(vulnerability)
    concrete = [item for item in identifiers if not _fuzzy(item)]
    if identifiers and not concrete:
        return False
    if concrete:
        trusted = [
            str(item.get("id") or "")
            for item in concrete
            if _confidence_rank(str(item.get("confidence") or "")) >= 3
            or (identity is not None and _cpe_matches(str(item.get("id") or ""), *identity))
        ]
        if not trusted:
            return False
        if not vuln_cpes:
            return True
        return any(_same_software(cpe, known) for cpe in vuln_cpes for known in trusted)
    if identity is None or not vuln_cpes:
        return True
    name, version = identity
    return any(_cpe_matches(cpe, name, version) for cpe in vuln_cpes)


def _same_software(vulnerable: str, identified: str) -> bool:
    """The vulnerable CPE names the identified vendor and product, and its version."""
    vendor, product, version = _cpe_parts(vulnerable)
    known_vendor, known_product, known_version = _cpe_parts(identified)
    if not product or _compact(product) != _compact(known_product):
        return False
    if vendor and known_vendor and _compact(vendor) != _compact(known_vendor):
        return False
    if version in {"", "*", "-"} or known_version in {"", "*", "-"}:
        return True
    return version == known_version


def _cpe_identifiers(dependency: dict) -> list[dict]:
    found: list[dict] = []
    for key in ("vulnerabilityIds", "packages"):
        for block in dependency.get(key) or []:
            if isinstance(block, dict) and str(block.get("id") or "").startswith("cpe:"):
                found.append(block)
    return found


def _vulnerability_cpes(vulnerability: dict) -> list[str]:
    found: list[str] = []
    for block in vulnerability.get("vulnerableSoftware") or []:
        if not isinstance(block, dict):
            continue
        software = block.get("software")
        if isinstance(software, dict) and str(software.get("id") or "").startswith("cpe:"):
            found.append(str(software["id"]))
        elif str(block.get("id") or "").startswith("cpe:"):
            found.append(str(block["id"]))
    return found


def _fuzzy(block: dict) -> bool:
    confidence = str(block.get("confidence") or "").strip().upper()
    notes = str(block.get("notes") or "").lower()
    return confidence == "LOW" or "fuzzy" in notes


def _confidence_rank(confidence: str) -> int:
    return {"HIGHEST": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(confidence.strip().upper(), 0)


def _purl(value: str) -> tuple[str, str] | None:
    if not value.startswith("pkg:"):
        return None
    body = value[4:].split("?", 1)[0].split("#", 1)[0]
    if "@" not in body or "/" not in body:
        return None
    coords, version = body.rsplit("@", 1)
    name = unquote(coords.split("/", 1)[1])
    if not name:
        return None
    return name, unquote(version)


def _name_version(file_name: str) -> tuple[str, str] | None:
    if ":" not in file_name or file_name.endswith(".jar") or "/" in file_name or "\\" in file_name:
        return None
    name, version = file_name.rsplit(":", 1)
    if not name or not _VERSION.match(version):
        return None
    return name, version


def _cpe_parts(cpe: str) -> tuple[str, str, str]:
    if cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        vendor = unquote(parts[3]) if len(parts) > 3 else ""
        product = unquote(parts[4]) if len(parts) > 4 else ""
        version = unquote(parts[5]) if len(parts) > 5 else ""
        return vendor, product, version
    if cpe.startswith("cpe:/"):
        parts = cpe.split(":")
        vendor = parts[2] if len(parts) > 2 else ""
        product = parts[3] if len(parts) > 3 else ""
        version = parts[4] if len(parts) > 4 else ""
        return vendor, product, version
    return "", "", ""


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _cpe_matches(cpe: str, name: str, version: str) -> bool:
    vendor, product, cpe_version = _cpe_parts(cpe)
    if not product or not _name_matches(name, vendor, product):
        return False
    if cpe_version and cpe_version not in {"*", "-"} and version and cpe_version != version:
        return False
    return True


def _name_matches(name: str, vendor: str, product: str) -> bool:
    scoped = name.startswith("@")
    plain = name[1:] if scoped else name
    product_key = _compact(product)
    if "/" not in plain:
        return product_key == _compact(plain)
    if not scoped:
        # A Maven group/artifact or a Go module path. The last segment is the
        # package; the namespace is not a CPE vendor.
        return product_key == _compact(plain.rsplit("/", 1)[1])
    scope, unscoped = plain.split("/", 1)
    if product_key == _compact(scope + "/" + unscoped) or product_key == _compact(scope + unscoped):
        return True
    return product_key == _compact(unscoped) and _compact(vendor) == _compact(scope)
