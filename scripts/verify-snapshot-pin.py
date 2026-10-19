#!/usr/bin/env python3
"""Prove one snapshot manifest against a pinned trust file and against empty trust.

Exit 0 when the pinned trust file verifies the signature, a tampered manifest
is refused, a manifest with the signature removed is refused, and an empty
trust file still accepts the same bytes as unsigned. When ``--zip`` is set,
its sha256 must match the manifest checksum.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.errors import SnapshotRefused  # noqa: E402
from checkstead.snapshot import parse_manifest, sha256_file  # noqa: E402
from checkstead.snapshot_auth import load_trust, verify_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--trust", required=True)
    parser.add_argument("--zip")
    args = parser.parse_args()
    manifest = parse_manifest(Path(args.manifest).read_text(encoding="utf-8"))
    trust = load_trust(Path(args.trust))
    if not trust.keys:
        print("The trust file has no keys. Pin the public key before this proof.", file=sys.stderr)
        return 2
    signed = verify_manifest(manifest, trust)
    if signed.status != "signed" or not signed.key_id:
        print("The pinned key did not verify the manifest.", file=sys.stderr)
        return 1
    print(f"verified key {signed.key_id}")

    tampered = dict(manifest)
    tampered["checksum"] = "0" * 64
    try:
        verify_manifest(tampered, trust)
    except SnapshotRefused as exc:
        print(f"tampered manifest refused: {exc}")
    else:
        print("A tampered manifest was accepted.", file=sys.stderr)
        return 1

    missing = {field: manifest[field] for field in manifest if field != "signature"}
    try:
        verify_manifest(missing, trust)
    except SnapshotRefused as exc:
        print(f"missing signature refused: {exc}")
    else:
        print("A missing signature was accepted.", file=sys.stderr)
        return 1

    empty = load_trust({"format": 1, "keys": []})
    unsigned = verify_manifest(manifest, empty)
    if unsigned.status != "unsigned":
        print("Empty trust treated a signature as verified.", file=sys.stderr)
        return 1
    print("empty trust accepts the manifest as unsigned")

    if args.zip:
        actual = sha256_file(Path(args.zip))
        expected = manifest["checksum"]
        if actual.lower() != expected.lower():
            print("The zip checksum does not match the manifest.", file=sys.stderr)
            return 1
        print("checksum matches")
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()
    print(f"manifest sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
