"""Snapshot key creation, trust entries, rotation, and the updater's verified seed."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import sys
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from checkstead.cli import main  # noqa: E402
from checkstead.errors import SnapshotRefused  # noqa: E402
from checkstead.snapshot import parse_manifest  # noqa: E402
from checkstead.snapshot_auth import load_trust, sign_manifest, verify_manifest  # noqa: E402
from test_phase1 import FixtureServer, manifest_for, write_zip  # noqa: E402


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class KeyCommandTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "key-management" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)

    def generate(self, key_id: str, not_after: str | None = None) -> tuple[Path, dict]:
        out = self.root / f"{key_id}.pem"
        args = ["snapshot-key", "generate", "--id", key_id, "--out", str(out)]
        if not_after:
            args += ["--not-after", not_after]
        code, stdout, _ = run_cli(*args)
        self.assertEqual(code, 0)
        return out, json.loads(stdout)

    def manifest(self, moment: str = "2026-10-06T01:00:00Z") -> dict:
        return parse_manifest(
            json.dumps(
                {
                    "format": 1,
                    "engineVersion": "13.0.0",
                    "snapshotTime": moment,
                    "checksum": "a" * 64,
                    "database": "checkstead-db.zip",
                }
            )
        )

    def test_generate_writes_a_private_file_and_prints_only_the_public_entry(self) -> None:
        private, entry = self.generate("checkstead-2026-10")
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        self.assertIn("PRIVATE KEY", private.read_text(encoding="utf-8"))
        self.assertEqual(entry["id"], "checkstead-2026-10")
        self.assertEqual(entry["status"], "current")
        self.assertNotIn("PRIVATE", json.dumps(entry))
        trust = load_trust({"format": 1, "keys": [entry]})
        signed = sign_manifest(self.manifest(), private.read_text(encoding="utf-8"), entry["id"], trust)
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(signed)), trust).status, "signed")

    def test_generate_refuses_to_overwrite(self) -> None:
        private, _ = self.generate("one")
        before = private.read_bytes()
        code, _, err = run_cli("snapshot-key", "generate", "--id", "one", "--out", str(private))
        self.assertNotEqual(code, 0)
        self.assertIn("Refusing to overwrite", err)
        self.assertEqual(private.read_bytes(), before)

    def test_public_reads_the_secret_from_the_environment(self) -> None:
        private, entry = self.generate("ci-key")
        with mock.patch.dict(os.environ, {"CHECKSTEAD_SNAPSHOT_SIGNING_KEY": private.read_text(encoding="utf-8")}):
            code, stdout, _ = run_cli("snapshot-key", "public", "--id", "ci-key")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["publicKeyPem"], entry["publicKeyPem"])

    def test_bad_ids_and_dates_are_refused(self) -> None:
        self.assertNotEqual(run_cli("snapshot-key", "generate", "--id", "../x", "--out", str(self.root / "k"))[0], 0)
        self.assertNotEqual(
            run_cli("snapshot-key", "generate", "--id", "ok", "--out", str(self.root / "k"), "--not-after", "soon")[0],
            0,
        )

    def test_rotation_keeps_old_snapshots_valid_and_stops_the_old_key_signing(self) -> None:
        old_private, old_entry = self.generate("2026-10", not_after="2026-12-31")
        new_private, new_entry = self.generate("2027-01")
        old_signed = sign_manifest(
            self.manifest("2026-11-01T01:00:00Z"),
            old_private.read_text(encoding="utf-8"),
            "2026-10",
            load_trust({"format": 1, "keys": [old_entry]}),
        )
        old_entry["status"] = "retired"
        rotated = load_trust({"format": 1, "keys": [old_entry, new_entry]})
        # A snapshot signed before rotation still verifies.
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(old_signed)), rotated).key_id, "2026-10")
        # The retired key can no longer sign.
        with self.assertRaises(Exception):
            sign_manifest(self.manifest(), old_private.read_text(encoding="utf-8"), "2026-10", rotated)
        # A snapshot dated after notAfter is refused even with a valid signature.
        late = sign_manifest(
            self.manifest("2027-01-02T01:00:00Z"),
            old_private.read_text(encoding="utf-8"),
            "2026-10",
            load_trust({"format": 1, "keys": [dict(old_entry, status="current")]}),
        )
        with self.assertRaises(SnapshotRefused):
            verify_manifest(parse_manifest(json.dumps(late)), rotated)
        # The new key signs and verifies.
        new_signed = sign_manifest(self.manifest(), new_private.read_text(encoding="utf-8"), "2027-01", rotated)
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(new_signed)), rotated).status, "signed")


class SeedTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "seed" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)
        self.server = FixtureServer()
        self.addCleanup(self.server.close)

    def test_a_verified_snapshot_is_extracted(self) -> None:
        archive = self.root / "db.zip"
        write_zip(archive, "seed")
        self.server.manifest = manifest_for(archive, "2026-10-06T01:00:00Z")
        self.server.zip_bytes = archive.read_bytes()
        dest = self.root / "data"
        code, stdout, err = run_cli(
            "seed-data", "--url", self.server.manifest_url, "--dest", str(dest), "--cache", str(self.root / "cache")
        )
        self.assertEqual(code, 0, err)
        self.assertIn("seed: 2026-10-06T01:00:00Z", stdout)
        self.assertTrue((dest / "FIXTURE").is_file())

    def test_a_tampered_snapshot_leaves_no_seed(self) -> None:
        archive = self.root / "db.zip"
        write_zip(archive, "seed")
        self.server.manifest = manifest_for(archive, "2026-10-06T01:00:00Z")
        self.server.zip_bytes = b"PK-not-the-published-zip"
        dest = self.root / "data"
        code, _, err = run_cli(
            "seed-data", "--url", self.server.manifest_url, "--dest", str(dest), "--cache", str(self.root / "cache")
        )
        self.assertNotEqual(code, 0)
        self.assertIn("checksum", err)
        self.assertFalse(dest.exists())

    def test_the_updater_seeds_and_rebuilds_weekly(self) -> None:
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        self.assertIn("checkstead seed-data", script)
        self.assertIn('date -u +%u)" == "7"', script)
        self.assertIn("CHECKSTEAD_FULL_REBUILD", script)
        self.assertLess(script.index("checkstead seed-data"), script.index("  --updateonly \\\n"))
        workflow = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        self.assertIn("timeout-minutes: 330", workflow)
        self.assertIn("full_rebuild", workflow)
