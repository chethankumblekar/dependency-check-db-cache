"""Direct or transitive, and production or dev, from the project's own manifests.

A devDependency, or a lockfile entry marked dev, is dev. That is a different
bucket from production. The scan does not contact a vulnerability feed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from xml.etree import ElementTree

_SKIP = {"node_modules", ".git", "dist", "build", ".next"}
_RANK = {
    ("direct", "production"): 4,
    ("direct", "dev"): 3,
    ("transitive", "production"): 2,
    ("transitive", "dev"): 1,
}


class RoleIndex:
    def __init__(self) -> None:
        self._exact: dict[tuple[str, str], tuple[str, str]] = {}
        self._by_name: dict[str, tuple[str, str]] = {}

    @property
    def empty(self) -> bool:
        return not self._exact and not self._by_name

    def add(self, name: str, version: str, role: tuple[str, str]) -> None:
        cleaned = name.strip()
        if not cleaned:
            return
        self._keep(self._by_name, cleaned, role)
        if version:
            self._keep(self._exact, (cleaned, version.strip()), role)

    def lookup(self, name: str, version: str) -> tuple[str, str]:
        options = []
        exact = self._exact.get((name, version))
        if exact is not None:
            options.append(exact)
        named = self._by_name.get(name)
        if named is not None:
            options.append(named)
        if not options:
            return ("transitive", "production")
        return max(options, key=lambda role: _RANK[role])

    @staticmethod
    def _keep(store: dict, key: object, role: tuple[str, str]) -> None:
        current = store.get(key)
        if current is None or _RANK[role] > _RANK[current]:
            store[key] = role


def roles_from_paths(paths: list[Path]) -> RoleIndex:
    index = RoleIndex()
    for path in paths:
        root = path if path.is_dir() else path.parent
        if not root.is_dir():
            continue
        for directory, dirnames, filenames in _walk(root):
            dirnames[:] = [name for name in dirnames if name not in _SKIP]
            current = Path(directory)
            if "package.json" in filenames:
                _package_json(current / "package.json", index)
            if "package-lock.json" in filenames:
                _package_lock(current / "package-lock.json", index)
            if "pnpm-lock.yaml" in filenames:
                _pnpm_lock(current / "pnpm-lock.yaml", index)
            if "pom.xml" in filenames:
                _pom(current / "pom.xml", index)
    return index


def _walk(root: Path):
    if root.name in _SKIP:
        return
    yield from os.walk(root)


def _read_json(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _package_json(path: Path, index: RoleIndex) -> None:
    payload = _read_json(path)
    if payload is None:
        return
    prod = _names(payload.get("dependencies")) | _names(payload.get("optionalDependencies")) | _names(
        payload.get("peerDependencies")
    )
    dev = _names(payload.get("devDependencies")) - prod
    for name in prod:
        index.add(name, "", ("direct", "production"))
    for name in dev:
        index.add(name, "", ("direct", "dev"))


def _names(value: object) -> set[str]:
    if not isinstance(value, dict):
        return set()
    return {str(name) for name in value if str(name).strip()}


def _package_lock(path: Path, index: RoleIndex) -> None:
    payload = _read_json(path)
    if payload is None:
        return
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for location, meta in packages.items():
            if location == "" or not isinstance(meta, dict):
                continue
            name = str(meta.get("name") or "").strip()
            if not name and "node_modules/" in str(location):
                name = str(location).rsplit("node_modules/", 1)[-1]
            version = str(meta.get("version") or "")
            dev = bool(meta.get("dev") or meta.get("devOptional"))
            _lock_role(index, name, version, dev)
        return
    _legacy_lock(payload.get("dependencies"), index)


def _legacy_lock(node: object, index: RoleIndex) -> None:
    if not isinstance(node, dict):
        return
    for name, meta in node.items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("version") or "")
        dev = bool(meta.get("dev"))
        _lock_role(index, str(name), version, dev)
        _legacy_lock(meta.get("dependencies"), index)


def _lock_role(index: RoleIndex, name: str, version: str, dev: bool) -> None:
    known = index.lookup(name, version)
    if known[0] == "direct":
        index.add(name, version, known)
        return
    index.add(name, version, ("transitive", "dev" if dev else "production"))


def _pnpm_lock(path: Path, index: RoleIndex) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    section = ""
    bucket = ""
    current = ""
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()
        if indent == 0 and text.endswith(":"):
            section = text[:-1]
            bucket = ""
            current = ""
            continue
        if section == "importers" and indent == 4 and text.endswith(":"):
            bucket = text[:-1]
            current = ""
            continue
        if section == "importers" and bucket in {"dependencies", "devDependencies"} and indent == 6 and text.endswith(":"):
            current = text[:-1].strip("'\"")
            role = ("direct", "dev" if bucket == "devDependencies" else "production")
            index.add(current, "", role)
            continue
        if section == "importers" and current and text.startswith("version:"):
            version = text.split(":", 1)[1].strip().strip("'\"")
            version = version.split("(")[0]
            role = ("direct", "dev" if bucket == "devDependencies" else "production")
            index.add(current, version, role)
            continue
        if section == "packages" and indent == 2 and text.endswith(":"):
            current = text[:-1].strip("'\"")
            name, _, version = current.rpartition("@")
            if name.startswith("@"):
                # @scope/name@version rpartition splits at the version @
                pass
            if name and version:
                index.add(name, version, ("transitive", "production"))
            continue
        if section == "packages" and current and text == "dev: true":
            name, _, version = current.rpartition("@")
            if name and version:
                known = index.lookup(name, version)
                if known[0] != "direct":
                    index.add(name, version, ("transitive", "dev"))


def _pom(path: Path, index: RoleIndex) -> None:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError):
        return
    ns = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
    for deps in root.findall(f"{ns}dependencies"):
        for dep in deps.findall(f"{ns}dependency"):
            group = (dep.findtext(f"{ns}groupId") or "").strip()
            artifact = (dep.findtext(f"{ns}artifactId") or "").strip()
            scope = (dep.findtext(f"{ns}scope") or "compile").strip()
            if not artifact:
                continue
            role = ("direct", "dev" if scope == "test" else "production")
            index.add(artifact, "", role)
            if group:
                index.add(f"{group}:{artifact}", "", role)
