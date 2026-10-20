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
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

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


def trust_source() -> Path:
    """The trust store in use: ``CHECKSTEAD_SNAPSHOT_TRUST``, or the one shipped here.

    A company that runs its own updater and mirror pins its own key this way.
    The override replaces the shipped keys rather than adding to them.
    """
    override = os.environ.get("CHECKSTEAD_SNAPSHOT_TRUST", "").strip()
    return Path(override) if override else TRUST_FILE


def load_trust(source: Path | dict | None = None) -> TrustStore:
    override = source is None and bool(os.environ.get("CHECKSTEAD_SNAPSHOT_TRUST", "").strip())
    if source is None:
        source = trust_source()
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
    if override and not keys:
        # An empty replacement would turn signature checks off. That is a
        # downgrade, not a configuration.
        raise ChecksteadError(
            "CHECKSTEAD_SNAPSHOT_TRUST names a trust store with no keys. "
            "It has to pin at least one public key."
        )
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
    try:
        _load_public(pem)
    except SnapshotRefused as exc:
        raise ChecksteadError(f"Snapshot trust store key {key_id} is not an Ed25519 public key.") from exc
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
        # A signature is not authenticity until a trust root is configured.
        # Refusing it here would break checksummed scans the day the publisher
        # starts signing, which is before the public key can be pinned.
        if signature_required(store):
            raise SnapshotRefused(f"Snapshot signature key {parsed['keyId']} is not pinned.")
        return Authenticity("unsigned", "")
    published = _snapshot_day(manifest.get("snapshotTime"))
    if key.not_after is not None and published > key.not_after:
        raise SnapshotRefused(
            f"Snapshot signature key {key.key_id} is not accepted for this snapshot."
        )
    raw = base64.b64decode(parsed["value"])
    if not _verify(key.public_pem, canonical_payload(manifest), raw):
        raise SnapshotRefused("Snapshot signature does not verify.")
    return Authenticity("signed", key.key_id)


def sign_manifest(
    manifest: dict,
    private_pem: str,
    key_id: str,
    trust: TrustStore | None = None,
) -> dict:
    """Sign a parsed manifest.

    An empty trust file is allowed. The updater has to be able to sign the
    next snapshot before that public key is pinned, because pinning first
    makes every current unsigned cache fail. When the key id is already
    pinned, it must be ``current`` and the private key must match it.
    """
    store = trust if trust is not None else load_trust()
    if "PRIVATE KEY" not in private_pem:
        raise ChecksteadError("Snapshot signing key is not a private key.")
    pinned = store.keys.get(key_id)
    if pinned is not None and pinned.status != "current":
        raise ChecksteadError(f"Snapshot signing key {key_id} is not a current pinned key.")
    unsigned = {field: manifest[field] for field in SIGNED_FIELDS}
    payload = canonical_payload(unsigned)
    signature = _sign(private_pem, payload)
    check_pem = pinned.public_pem if pinned is not None else public_pem_for(private_pem)
    if not _verify(check_pem, payload, signature):
        if pinned is not None:
            raise ChecksteadError("Snapshot signing key does not match the pinned public key.")
        raise ChecksteadError("Snapshot signing key could not be checked.")
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


def _load_private(private_pem: str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ChecksteadError("Snapshot signing key is not a private key.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ChecksteadError("Snapshot signing key is not an Ed25519 private key.")
    return key


def _load_public(public_pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise SnapshotRefused("Snapshot trust store public key is not readable.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SnapshotRefused("Snapshot trust store key is not an Ed25519 public key.")
    return key


def public_pem_for(private_pem: str) -> str:
    """The PEM public key that pairs with a private signing key. It is safe to publish."""
    key = _load_private(private_pem)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _sign(private_pem: str, payload: bytes) -> bytes:
    return _load_private(private_pem).sign(payload)


def _verify(public_pem: str, payload: bytes, signature: bytes) -> bool:
    try:
        _load_public(public_pem).verify(signature, payload)
    except InvalidSignature:
        return False
    return True
