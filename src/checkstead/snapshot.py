from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import OpenerDirector

from checkstead.archive import ArchiveRejected
from checkstead.archive import safe_extract as extract_archive
from checkstead.engine import pinned_engine
from checkstead.errors import ChecksteadError, SnapshotRefused
from checkstead.http import download, read_text
from checkstead.snapshot_auth import Authenticity, TrustStore, load_trust, signature_fields, verify_manifest

SNAPSHOT_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MANIFEST_FORMAT = 1


@dataclass(frozen=True)
class Snapshot:
    engine_version: str
    snapshot_time: str
    checksum: str
    database_path: Path
    data_dir: Path
    manifest_path: Path
    authenticity: str = "unsigned"
    signature_key_id: str = ""
    freshness: str = "unknown"
    age_days: int | None = None
    cache: str = "unknown"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def max_snapshot_age_days() -> int:
    """Days after which a snapshot is stale. The default does not fail a scan."""
    raw = os.environ.get("CHECKSTEAD_SNAPSHOT_MAX_AGE_DAYS", "7").strip() or "7"
    if not re.fullmatch(r"[0-9]+", raw):
        raise ChecksteadError("CHECKSTEAD_SNAPSHOT_MAX_AGE_DAYS must be a non-negative integer.")
    return int(raw)


def classify_freshness(snapshot_time: str, today: date) -> tuple[str, int]:
    """``current`` is age 0 or 1. ``aging`` is older, up to the maximum. ``stale`` is past it.

    A negative age means the manifest timestamp is after the scan's UTC day.
    That is reported as current so a clock skew of one day does not fail a scan,
    and the negative age is still returned.
    """
    published = datetime.strptime(snapshot_time, "%Y-%m-%dT%H:%M:%SZ").date()
    age = (today - published).days
    if age > max_snapshot_age_days():
        return "stale", age
    if age > 1:
        return "aging", age
    return "current", age


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
    if not isinstance(database, str) or not DATABASE_NAME_RE.fullmatch(database):
        raise SnapshotRefused("Snapshot manifest database name must be a file name.")
    checksum = _normalize_checksum(manifest.get("checksum"))
    parsed = {
        "format": MANIFEST_FORMAT,
        "engineVersion": engine.strip(),
        "snapshotTime": snapshot_time,
        "checksum": checksum,
        "database": database.strip(),
    }
    signature = signature_fields(manifest.get("signature"))
    if signature is not None:
        parsed["signature"] = signature
    return parsed


def _checksums_match(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.lower(), expected.lower())


def safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a snapshot or repository zip, refusing members that escape dest."""
    try:
        extract_archive(zip_path, dest)
    except ArchiveRejected as exc:
        raise SnapshotRefused(str(exc)) from exc
    except zipfile.BadZipFile as exc:
        raise SnapshotRefused(f"Snapshot archive is not a zip file: {exc}") from exc


def resolve_snapshot(
    manifest_url: str,
    cache_dir: Path,
    today,
    opener: OpenerDirector | None = None,
    trust: TrustStore | None = None,
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
            return _resolve_snapshot(manifest_url, cache_dir, today, opener, trust)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _resolve_snapshot(
    manifest_url: str,
    cache_dir: Path,
    today,
    opener: OpenerDirector | None,
    trust: TrustStore | None,
) -> Snapshot:
    day_dir = cache_dir / today.isoformat()
    day_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = day_dir / "manifest.json"
    database_path = day_dir / "checkstead-db.zip"
    data_dir = day_dir / "data"

    if manifest_path.is_file() and database_path.is_file():
        manifest = parse_manifest(manifest_path.read_text(encoding="utf-8"))
        authenticity = _accept_manifest(manifest, trust)
        actual = sha256_file(database_path)
        if not _checksums_match(actual, manifest["checksum"]):
            raise SnapshotRefused(
                "The cached snapshot no longer matches its manifest. "
                f"Remove {day_dir} and scan again."
            )
        return _snapshot(manifest, database_path, data_dir, manifest_path, today, "hit", authenticity)

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
        raise ChecksteadError(
            f"Snapshot manifest request failed: HTTP {exc.code}. The snapshot is unavailable.{hint}"
        ) from exc
    except URLError as exc:
        raise ChecksteadError(
            f"Could not download the snapshot manifest: {exc.reason}. The snapshot is unavailable."
        ) from exc
    manifest = parse_manifest(payload)
    authenticity = _accept_manifest(manifest, trust)
    database_url = _database_url(manifest_url, manifest["database"])
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
    return _snapshot(manifest, database_path, data_dir, manifest_path, today, "fetched", authenticity)


def _database_url(manifest_url: str, name: str) -> str:
    """Join a file name onto the manifest URL and refuse a different host or scheme."""
    resolved = urljoin(manifest_url, name)
    base = urlsplit(manifest_url)
    target = urlsplit(resolved)
    same_host = (target.hostname or "").rstrip(".").lower() == (base.hostname or "").rstrip(".").lower()
    if (
        target.scheme != base.scheme
        or not same_host
        or target.username
        or target.password
        or target.query
        or target.fragment
    ):
        raise SnapshotRefused("Snapshot database URL does not stay on the manifest host.")
    return resolved


def _accept_manifest(manifest: dict, trust: TrustStore | None) -> Authenticity:
    store = trust if trust is not None else load_trust()
    return verify_manifest(manifest, store)


def _snapshot(
    manifest: dict,
    database_path: Path,
    data_dir: Path,
    manifest_path: Path,
    today: date,
    cache: str,
    authenticity: Authenticity,
) -> Snapshot:
    freshness, age = classify_freshness(manifest["snapshotTime"], today)
    if freshness == "stale" and os.environ.get("CHECKSTEAD_FAIL_STALE_SNAPSHOT", "").strip() == "1":
        raise SnapshotRefused(
            f"Snapshot {manifest['snapshotTime']} is stale ({age} days, "
            f"maximum {max_snapshot_age_days()}). "
            "Unset CHECKSTEAD_FAIL_STALE_SNAPSHOT to scan with this cache."
        )
    if freshness == "stale":
        print(
            f"checkstead: snapshot {manifest['snapshotTime']} is stale "
            f"({age} days, maximum {max_snapshot_age_days()}). Continuing. "
            "Set CHECKSTEAD_FAIL_STALE_SNAPSHOT=1 to refuse a stale snapshot.",
            file=sys.stderr,
        )
    return Snapshot(
        engine_version=manifest["engineVersion"],
        snapshot_time=manifest["snapshotTime"],
        checksum=manifest["checksum"],
        database_path=database_path,
        data_dir=data_dir,
        manifest_path=manifest_path,
        authenticity=authenticity.status,
        signature_key_id=authenticity.key_id,
        freshness=freshness,
        age_days=age,
        cache=cache,
    )
