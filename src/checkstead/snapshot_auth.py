"""Snapshot signature checks against public keys pinned in this client.

The signature binds the manifest fields that name the zip checksum. It is
not a second publisher. A person who can replace the pinned public key and
publish a release can still produce a signature this client accepts. A
release upload that does not have the private key cannot.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from checkstead.errors import ChecksteadError, SnapshotRefused

TRUST_FILE = Path(__file__).with_name("snapshot_trust.json")
ALGORITHM = "ed25519"
SIGNED_FIELDS = ("checksum", "database", "engineVersion", "format", "snapshotTime")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class TrustKey:
    key_id: str
    status: str
    public_pem: str
    not_after: date | None


@dataclass(frozen=True)
class TrustStore:
    keys: dict[str, TrustKey]


@dataclass(frozen=True)
class Authenticity:
    """``signed`` means a pinned key verified the manifest. ``unsigned`` does not."""

    status: str
    key_id: str


def canonical_payload(manifest: dict) -> bytes:
    """Bytes that a signature covers. The signature object itself is not included."""
    body = {}
    for field in SIGNED_FIELDS:
        if field not in manifest:
            raise SnapshotRefused("Snapshot manifest is missing a signed field.")
        body[field] = manifest[field]
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_trust(source: Path | dict | None = None) -> TrustStore:
    if source is None:
        source = TRUST_FILE
    if isinstance(source, Path):
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ChecksteadError(f"Snapshot trust store is not readable JSON: {source}") from exc
    else:
        payload = source
    if not isinstance(payload, dict) or payload.get("format") != 1:
        raise ChecksteadError("Snapshot trust store format is not 1.")
    entries = payload.get("keys")
    if not isinstance(entries, list):
        raise ChecksteadError("Snapshot trust store has no key list.")
    keys: dict[str, TrustKey] = {}
    for entry in entries:
        key = _trust_key(entry)
        if key.key_id in keys:
            raise ChecksteadError(f"Snapshot trust store repeats key {key.key_id}.")
        keys[key.key_id] = key
    return TrustStore(keys)


def _trust_key(entry: object) -> TrustKey:
    if not isinstance(entry, dict):
        raise ChecksteadError("Snapshot trust store key is not an object.")
    key_id = entry.get("id")
    status = entry.get("status")
    pem = entry.get("publicKeyPem")
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise ChecksteadError("Snapshot trust store key id is not valid.")
    if status not in {"current", "retired"}:
        raise ChecksteadError(f"Snapshot trust store key {key_id} has an unknown status.")
    if not isinstance(pem, str) or "BEGIN PUBLIC KEY" not in pem or "PRIVATE KEY" in pem:
        raise ChecksteadError(f"Snapshot trust store key {key_id} is not a public key.")
    raw_after = entry.get("notAfter")
    not_after: date | None = None
    if raw_after is not None:
        if not isinstance(raw_after, str) or not DAY.fullmatch(raw_after):
            raise ChecksteadError(f"Snapshot trust store key {key_id} has a bad notAfter.")
        not_after = date.fromisoformat(raw_after)
    return TrustKey(key_id, status, pem, not_after)


def signature_fields(value: object) -> dict | None:
    """Return the signature object, or None when the manifest is unsigned."""
    if value is None:
        return None
    if not isinstance(value, dict):
        raise SnapshotRefused("Snapshot signature is not valid.")
    key_id = value.get("keyId")
    algorithm = value.get("algorithm")
    encoded = value.get("value")
    if not isinstance(key_id, str) or not KEY_ID.fullmatch(key_id):
        raise SnapshotRefused("Snapshot signature is not valid.")
    if not isinstance(algorithm, str) or algorithm != ALGORITHM:
        raise SnapshotRefused("Snapshot signature algorithm is not supported.")
    if not isinstance(encoded, str):
        raise SnapshotRefused("Snapshot signature is not valid.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise SnapshotRefused("Snapshot signature is not valid.") from exc
    if not raw:
        raise SnapshotRefused("Snapshot signature is not valid.")
    return {"keyId": key_id, "algorithm": ALGORITHM, "value": encoded.strip()}


def signature_required(trust: TrustStore) -> bool:
    """Unsigned checksummed snapshots stay valid until a trust root is configured.

    ``CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE=1`` is the explicit mode with an
    empty trust file. Any pinned public key is also that mode: a missing
    signature is then a failure. An empty trust file leaves the mode off.
    """
    if os.environ.get("CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE", "").strip() == "1":
        return True
    return bool(trust.keys)


def verify_manifest(manifest: dict, trust: TrustStore | None = None) -> Authenticity:
    """Fail closed on a bad signature. An absent signature stays unsigned until required."""
    store = trust if trust is not None else load_trust()
    parsed = signature_fields(manifest.get("signature"))
    if parsed is None:
        if signature_required(store):
            if store.keys:
                raise SnapshotRefused(
                    "Snapshot signature is missing. This client has a snapshot trust root."
                )
            raise SnapshotRefused("Snapshot signature is missing.")
        return Authenticity("unsigned", "")
    key = store.keys.get(parsed["keyId"])
    if key is None:
        raise SnapshotRefused(f"Snapshot signature key {parsed['keyId']} is not pinned.")
    published = _snapshot_day(manifest.get("snapshotTime"))
    if key.not_after is not None and published > key.not_after:
        raise SnapshotRefused(
            f"Snapshot signature key {key.key_id} is not accepted for this snapshot."
        )
    raw = base64.b64decode(parsed["value"])
    if not _openssl_verify(key.public_pem, canonical_payload(manifest), raw):
        raise SnapshotRefused("Snapshot signature does not verify.")
    return Authenticity("signed", key.key_id)


def sign_manifest(
    manifest: dict,
    private_pem: str,
    key_id: str,
    trust: TrustStore | None = None,
) -> dict:
    """Sign a parsed manifest. The private key must match a current pinned key."""
    store = trust if trust is not None else load_trust()
    key = store.keys.get(key_id)
    if key is None or key.status != "current":
        raise ChecksteadError(f"Snapshot signing key {key_id} is not a current pinned key.")
    if "PRIVATE KEY" not in private_pem:
        raise ChecksteadError("Snapshot signing key is not a private key.")
    unsigned = {field: manifest[field] for field in SIGNED_FIELDS}
    payload = canonical_payload(unsigned)
    signature = _openssl_sign(private_pem, payload)
    if not _openssl_verify(key.public_pem, payload, signature):
        raise ChecksteadError("Snapshot signing key does not match the pinned public key.")
    signed = dict(unsigned)
    signed["signature"] = {
        "keyId": key_id,
        "algorithm": ALGORITHM,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    return signed


def _snapshot_day(value: object) -> date:
    if not isinstance(value, str):
        raise SnapshotRefused("Snapshot manifest time must be UTC, like 2026-10-06T01:00:00Z.")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").date()
    except ValueError as exc:
        raise SnapshotRefused("Snapshot manifest time must be UTC, like 2026-10-06T01:00:00Z.") from exc


def _openssl_sign(private_pem: str, payload: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        key_path = directory / "key.pem"
        data_path = directory / "payload"
        signature_path = directory / "signature"
        key_path.write_text(private_pem, encoding="utf-8")
        key_path.chmod(0o600)
        data_path.write_bytes(payload)
        completed = _openssl(
            "pkeyutl",
            "-sign",
            "-inkey",
            str(key_path),
            "-rawin",
            "-in",
            str(data_path),
            "-out",
            str(signature_path),
        )
        if completed.returncode != 0 or not signature_path.is_file():
            raise ChecksteadError("Could not sign the snapshot manifest.")
        return signature_path.read_bytes()


def _openssl_verify(public_pem: str, payload: bytes, signature: bytes) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        key_path = directory / "key.pem"
        data_path = directory / "payload"
        signature_path = directory / "signature"
        key_path.write_text(public_pem, encoding="utf-8")
        data_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        completed = _openssl(
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(key_path),
            "-rawin",
            "-in",
            str(data_path),
            "-sigfile",
            str(signature_path),
        )
        return completed.returncode == 0


def _openssl(*args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["openssl", *args],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ChecksteadError("openssl is required to verify a snapshot signature.") from exc
