"""Snapshot signatures and freshness. These tests do not call the NVD."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.errors import ChecksteadError, SnapshotRefused  # noqa: E402
from checkstead.snapshot import (  # noqa: E402
    classify_freshness,
    parse_manifest,
    resolve_snapshot,
    sha256_file,
    write_manifest,
)
from checkstead.snapshot_auth import load_trust, sign_manifest, verify_manifest  # noqa: E402


def _keys(directory: Path, name: str) -> tuple[str, str]:
    private = directory / f"{name}.pem"
    public = directory / f"{name}.pub"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    return private.read_text(encoding="utf-8"), public.read_text(encoding="utf-8")


def _trust(*entries: dict):
    return load_trust({"format": 1, "keys": list(entries)})


def _entry(key_id: str, public_pem: str, status: str = "current", not_after: str | None = None) -> dict:
    entry = {"id": key_id, "status": status, "publicKeyPem": public_pem}
    if not_after is not None:
        entry["notAfter"] = not_after
    return entry


class SignatureTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "snapshot-auth" / self.id().split(".")[-1]
        subprocess.run(["rm", "-rf", str(self.root)], check=True)
        self.root.mkdir(parents=True)
        self.private, self.public = _keys(self.root, "current")
        self.trust = _trust(_entry("2026-10", self.public))
        self._saved = {
            key: os.environ.get(key)
            for key in ("CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE", "CHECKSTEAD_FAIL_STALE_SNAPSHOT")
        }
        os.environ.pop("CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE", None)
        os.environ.pop("CHECKSTEAD_FAIL_STALE_SNAPSHOT", None)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _manifest(self, label: str = "db", when: str = "2026-10-06T01:00:00Z") -> dict:
        blob = self.root / f"{label}.zip"
        blob.write_bytes(f"fixture {label}\n".encode("utf-8"))
        written = write_manifest(blob, self.root / f"{label}.json", _time(when))
        return written

    def test_a_pinned_key_verifies_and_a_tampered_manifest_does_not(self) -> None:
        manifest = sign_manifest(self._manifest(), self.private, "2026-10", self.trust)
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(manifest)), self.trust).status, "signed")
        tampered = dict(manifest)
        tampered["snapshotTime"] = "2026-10-06T02:00:00Z"
        with self.assertRaises(SnapshotRefused) as raised:
            verify_manifest(tampered, self.trust)
        self.assertIn("does not verify", str(raised.exception))

    def test_missing_invalid_and_unpinned_signatures_are_refused(self) -> None:
        unsigned = self._manifest("unsigned")
        with self.assertRaises(SnapshotRefused) as keyed:
            verify_manifest(unsigned, self.trust)
        self.assertIn("trust root", str(keyed.exception))
        self.assertEqual(verify_manifest(unsigned, _trust()).status, "unsigned")
        os.environ["CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE"] = "1"
        with self.assertRaises(SnapshotRefused) as missing:
            verify_manifest(unsigned, _trust())
        self.assertIn("missing", str(missing.exception))
        os.environ.pop("CHECKSTEAD_REQUIRE_SNAPSHOT_SIGNATURE", None)

        signed = sign_manifest(self._manifest("signed"), self.private, "2026-10", self.trust)
        invalid = dict(signed)
        invalid["signature"] = dict(signed["signature"])
        invalid["signature"]["value"] = "AA" * 40
        with self.assertRaises(SnapshotRefused) as bad:
            verify_manifest(invalid, self.trust)
        self.assertIn("does not verify", str(bad.exception))

        other_private, other_public = _keys(self.root, "other")
        foreign = sign_manifest(
            self._manifest("foreign"),
            other_private,
            "other-key",
            _trust(_entry("other-key", other_public)),
        )
        with self.assertRaises(SnapshotRefused) as mismatch:
            verify_manifest(foreign, self.trust)
        self.assertIn("not pinned", str(mismatch.exception))

    def test_a_retired_key_verifies_until_not_after(self) -> None:
        retired = _trust(_entry("2026-10", self.public, status="retired", not_after="2026-10-06"))
        manifest = sign_manifest(self._manifest(), self.private, "2026-10", self.trust)
        self.assertEqual(verify_manifest(manifest, retired).status, "signed")
        with self.assertRaises(ChecksteadError):
            sign_manifest(self._manifest("later", "2026-10-07T01:00:00Z"), self.private, "2026-10", retired)
        resigned = sign_manifest(
            self._manifest("later-ok", "2026-10-07T01:00:00Z"),
            self.private,
            "2026-10",
            self.trust,
        )
        with self.assertRaises(SnapshotRefused) as expired:
            verify_manifest(resigned, retired)
        self.assertIn("not accepted", str(expired.exception))

    def test_the_shipped_trust_store_has_no_key_and_rejects_a_private_key(self) -> None:
        self.assertEqual(load_trust().keys, {})
        with self.assertRaises(ChecksteadError):
            load_trust({"format": 1, "keys": [_entry("2026-10", self.private)]})

    def test_a_modified_archive_is_refused_and_a_signed_download_is_accepted(self) -> None:
        blob = self.root / "checkstead-db.zip"
        blob.write_bytes(b"database-bytes\n")
        manifest = sign_manifest(
            write_manifest(blob, self.root / "manifest.json", _time("2026-10-06T01:00:00Z")),
            self.private,
            "2026-10",
            self.trust,
        )
        day = self.root / "cache" / "2026-10-06"
        day.mkdir(parents=True)
        (day / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        cached = day / "checkstead-db.zip"
        cached.write_bytes(b"tampered-bytes\n")
        with self.assertRaises(SnapshotRefused) as raised:
            resolve_snapshot(
                "https://example.invalid/manifest.json",
                self.root / "cache",
                date(2026, 10, 6),
                trust=self.trust,
            )
        self.assertIn("no longer matches", str(raised.exception))
        cached.write_bytes(blob.read_bytes())
        self.assertEqual(sha256_file(cached), manifest["checksum"])
        hit = resolve_snapshot(
            "https://example.invalid/manifest.json",
            self.root / "cache",
            date(2026, 10, 6),
            trust=self.trust,
        )
        self.assertEqual(hit.authenticity, "signed")
        self.assertEqual(hit.cache, "hit")
        self.assertEqual(hit.freshness, "current")
        self.assertEqual(hit.age_days, 0)

        server = _Server()
        self.addCleanup(server.close)
        server.manifest = json.dumps(manifest).encode("utf-8")
        server.zip_bytes = blob.read_bytes()
        fetched = resolve_snapshot(
            server.manifest_url,
            self.root / "fetch-cache",
            date(2026, 10, 6),
            trust=self.trust,
        )
        self.assertEqual(fetched.authenticity, "signed")
        self.assertEqual(fetched.signature_key_id, "2026-10")
        self.assertEqual(fetched.cache, "fetched")
        before = len(server.paths)
        again = resolve_snapshot(
            server.manifest_url,
            self.root / "fetch-cache",
            date(2026, 10, 6),
            trust=self.trust,
        )
        self.assertEqual(again.cache, "hit")
        self.assertEqual(len(server.paths), before)

    def test_freshness_warns_and_can_fail_without_calling_the_network(self) -> None:
        self.assertEqual(classify_freshness("2026-10-06T01:00:00Z", date(2026, 10, 6)), ("current", 0))
        self.assertEqual(classify_freshness("2026-10-06T01:00:00Z", date(2026, 10, 7)), ("current", 1))
        self.assertEqual(classify_freshness("2026-10-01T01:00:00Z", date(2026, 10, 5)), ("aging", 4))
        self.assertEqual(classify_freshness("2026-09-01T01:00:00Z", date(2026, 10, 6))[0], "stale")
        blob = self.root / "old.zip"
        blob.write_bytes(b"old\n")
        manifest = write_manifest(blob, self.root / "old.json", _time("2026-09-01T01:00:00Z"))
        day = self.root / "old-cache" / "2026-10-06"
        day.mkdir(parents=True)
        (day / "manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        (day / "checkstead-db.zip").write_bytes(blob.read_bytes())
        empty = _trust()
        stale = resolve_snapshot(
            "https://example.invalid/manifest.json",
            self.root / "old-cache",
            date(2026, 10, 6),
            trust=empty,
        )
        self.assertEqual(stale.freshness, "stale")
        self.assertEqual(stale.cache, "hit")
        self.assertGreater(stale.age_days or 0, 7)
        os.environ["CHECKSTEAD_FAIL_STALE_SNAPSHOT"] = "1"
        with self.assertRaises(SnapshotRefused) as raised:
            resolve_snapshot(
                "https://example.invalid/manifest.json",
                self.root / "old-cache",
                date(2026, 10, 6),
                trust=empty,
            )
        self.assertIn("stale", str(raised.exception))

    def test_an_unsigned_checksummed_cache_works_until_a_trust_root_exists(self) -> None:
        blob = self.root / "plain.zip"
        blob.write_bytes(b"checksummed\n")
        manifest = write_manifest(blob, self.root / "plain.json", _time("2026-10-06T01:00:00Z"))
        day = self.root / "plain-cache" / "2026-10-06"
        day.mkdir(parents=True)
        (day / "manifest.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        (day / "checkstead-db.zip").write_bytes(blob.read_bytes())
        kept = resolve_snapshot(
            "https://example.invalid/manifest.json",
            self.root / "plain-cache",
            date(2026, 10, 6),
            trust=_trust(),
        )
        self.assertEqual(kept.authenticity, "unsigned")
        self.assertEqual(kept.cache, "hit")
        with self.assertRaises(SnapshotRefused) as raised:
            resolve_snapshot(
                "https://example.invalid/manifest.json",
                self.root / "plain-cache",
                date(2026, 10, 6),
                trust=self.trust,
            )
        self.assertIn("trust root", str(raised.exception))
        self.assertTrue((day / "checkstead-db.zip").is_file())

    def test_the_updater_signs_only_when_a_key_is_configured(self) -> None:
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        self.assertIn("CHECKSTEAD_SNAPSHOT_SIGNING_KEY", script)
        self.assertIn("CHECKSTEAD_SNAPSHOT_KEY_ID", workflow)
        self.assertNotIn('echo "$CHECKSTEAD_SNAPSHOT_SIGNING_KEY"', script)
        self.assertNotIn("echo $CHECKSTEAD_SNAPSHOT_SIGNING_KEY", script)
        self.assertIn("secrets.CHECKSTEAD_SNAPSHOT_SIGNING_KEY", workflow)
        self.assertNotIn(self.private, script)


def _time(value: str):
    from datetime import datetime, timezone

    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class _Server:
    def __init__(self) -> None:
        self.manifest = b""
        self.zip_bytes = b""
        self.paths: list[str] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = urlparse(self.path).path
                outer.paths.append(path)
                if path == "/manifest.json":
                    body = outer.manifest
                elif path == "/checkstead-db.zip":
                    body = outer.zip_bytes
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                return

        return Handler

    @property
    def manifest_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/manifest.json"

    def close(self) -> None:
        self._httpd.shutdown()
        self._thread.join(timeout=5)
        self._httpd.server_close()
