from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import OpenerDirector

from checkstead.engine import pinned_engine
from checkstead.errors import ChecksteadError, SnapshotRefused
from checkstead.http import download, read_text

SNAPSHOT_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MANIFEST_FORMAT = 1


@dataclass(frozen=True)
class Snapshot:
    engine_version: str
    snapshot_time: str
    checksum: str
    database_path: Path
    data_dir: Path
    manifest_path: Path


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_snapshot_time(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ChecksteadError("Snapshot time must be timezone-aware UTC.")
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(database_zip: Path, moment: datetime | None = None) -> dict:
    """Manifest for a zip built by the pinned engine. The checksum is of the zip."""
    if not database_zip.is_file():
        raise ChecksteadError(f"Database zip not found: {database_zip}")
    return {
        "format": MANIFEST_FORMAT,
        "engineVersion": pinned_engine(),
        "snapshotTime": format_snapshot_time(moment or utc_now()),
        "checksum": sha256_file(database_zip),
        "database": "checkstead-db.zip",
    }


def write_manifest(database_zip: Path, dest: Path, moment: datetime | None = None) -> dict:
    manifest = build_manifest(database_zip, moment)
    dest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def _normalize_checksum(value: object) -> str:
    if not isinstance(value, str):
        raise SnapshotRefused("Snapshot manifest checksum is missing.")
    text = value.strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise SnapshotRefused("Snapshot manifest checksum is not a SHA-256 digest.")
    return text


def parse_manifest(payload: str) -> dict:
    try:
        manifest = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise SnapshotRefused(f"Snapshot manifest is not JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise SnapshotRefused("Snapshot manifest must be a JSON object.")
    if manifest.get("format") != MANIFEST_FORMAT:
        raise SnapshotRefused(
            f"Refusing snapshot manifest format {manifest.get('format')!r}. "
            f"This client reads format {MANIFEST_FORMAT}."
        )
    engine = manifest.get("engineVersion")
    if not isinstance(engine, str) or not engine.strip():
        raise SnapshotRefused("Snapshot manifest has no engine version.")
    pin = pinned_engine()
    if engine.strip() != pin:
        raise SnapshotRefused(
            f"Refusing snapshot built by Dependency-Check {engine.strip()}. "
            f"This Checkstead pin is {pin}."
        )
    snapshot_time = manifest.get("snapshotTime")
    if not isinstance(snapshot_time, str) or not SNAPSHOT_TIME_RE.fullmatch(snapshot_time):
        raise SnapshotRefused(
            "Snapshot manifest time must be UTC, like 2026-10-06T01:00:00Z."
        )
    database = manifest.get("database")
    if not isinstance(database, str) or not database.strip() or "/" in database or "\\" in database:
        raise SnapshotRefused("Snapshot manifest database name must be a file name.")
    checksum = _normalize_checksum(manifest.get("checksum"))
    return {
        "format": MANIFEST_FORMAT,
        "engineVersion": engine.strip(),
        "snapshotTime": snapshot_time,
        "checksum": checksum,
        "database": database.strip(),
    }


def _checksums_match(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.lower(), expected.lower())


def safe_extract(zip_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            target = (root / info.filename).resolve()
            if target != root and root not in target.parents:
                raise SnapshotRefused(f"Snapshot archive escapes its directory: {info.filename}")
        archive.extractall(root)


def resolve_snapshot(
    manifest_url: str,
    cache_dir: Path,
    today,
    opener: OpenerDirector | None = None,
) -> Snapshot:
    """Use the snapshot already cached for this UTC day, otherwise fetch and pin it.

    The first successful manifest of the UTC day is the snapshot every later scan
    that day names, even if the published manifest changes afterward.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    lock_path = cache_dir / ".lock"
    with lock_path.open("a", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _resolve_snapshot(manifest_url, cache_dir, today, opener)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _resolve_snapshot(
    manifest_url: str,
    cache_dir: Path,
    today,
    opener: OpenerDirector | None,
) -> Snapshot:
    day_dir = cache_dir / today.isoformat()
    day_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = day_dir / "manifest.json"
    database_path = day_dir / "checkstead-db.zip"
    data_dir = day_dir / "data"

    if manifest_path.is_file() and database_path.is_file():
        manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"))
        actual = sha256_file(database_path)
        if not _checksums_match(actual, manifest["checksum"]):
            raise SnapshotRefused(
                "The cached snapshot no longer matches its manifest. "
                f"Remove {day_dir} and scan again."
            )
        return Snapshot(
            engine_version=manifest["engineVersion"],
            snapshot_time=manifest["snapshotTime"],
            checksum=manifest["checksum"],
            database_path=database_path,
            data_dir=data_dir,
            manifest_path=manifest_path,
        )

    try:
        payload = read_text(manifest_url, opener)
    except HTTPError as exc:
        hint = ""
        if exc.code == 404:
            hint = (
                " If this is the public Checkstead snapshot, it has not been published yet."
                " Add the NVD_API_KEY repository secret and run the updater."
                " Checkstead does not ship a stand-in database."
            )
        raise ChecksteadError(f"Snapshot manifest request failed: HTTP {exc.code}.{hint}") from exc
    except URLError as exc:
        raise ChecksteadError(f"Could not download the snapshot manifest: {exc.reason}") from exc
    manifest = parse_manifest(payload)
    database_url = urljoin(manifest_url, manifest["database"])
    try:
        actual = download(database_url, database_path, opener)
    except Exception:
        database_path.unlink(missing_ok=True)
        raise
    if not _checksums_match(actual, manifest["checksum"]):
        database_path.unlink(missing_ok=True)
        raise SnapshotRefused(
            "Refusing snapshot: the database checksum does not match the manifest."
        )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return Snapshot(
        engine_version=manifest["engineVersion"],
        snapshot_time=manifest["snapshotTime"],
        checksum=manifest["checksum"],
        database_path=database_path,
        data_dir=data_dir,
        manifest_path=manifest_path,
    )
