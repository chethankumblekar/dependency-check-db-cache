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
        if os.name != "nt":  # Windows has no POSIX mode bits; ACLs apply instead.
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

    def test_an_offline_standby_key_takes_over_without_a_client_release(self) -> None:
        online_private, online_entry = self.generate("2026-10b")
        standby_private, standby_entry = self.generate("standby-2026-10")
        # Both are pinned as current in the release clients already have.
        shipped = load_trust({"format": 1, "keys": [online_entry, standby_entry]})
        before = sign_manifest(self.manifest("2026-11-01T01:00:00Z"), online_private.read_text(encoding="utf-8"), "2026-10b", shipped)
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(before)), shipped).key_id, "2026-10b")
        # The online key is lost: the updater signs with the standby, and the
        # same client verifies it.
        after = sign_manifest(self.manifest("2026-11-02T01:00:00Z"), standby_private.read_text(encoding="utf-8"), "standby-2026-10", shipped)
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(after)), shipped).key_id, "standby-2026-10")

    def test_a_compromised_key_is_removed_not_retired(self) -> None:
        stolen_private, stolen_entry = self.generate("2026-10", not_after="2026-10-31")
        _new_private, new_entry = self.generate("2026-11")
        retired = load_trust({"format": 1, "keys": [dict(stolen_entry, status="retired"), new_entry]})
        # notAfter compares the manifest's own date, which the signer writes.
        # Whoever holds a stolen key can backdate a manifest, and a retired
        # entry still accepts it. Retiring is for rotation, not compromise.
        backdated = sign_manifest(
            self.manifest("2026-10-15T01:00:00Z"),
            stolen_private.read_text(encoding="utf-8"),
            "2026-10",
            load_trust({"format": 1, "keys": [stolen_entry]}),
        )
        self.assertEqual(verify_manifest(parse_manifest(json.dumps(backdated)), retired).status, "signed")
        removed = load_trust({"format": 1, "keys": [new_entry]})
        with self.assertRaises(SnapshotRefused):
            verify_manifest(parse_manifest(json.dumps(backdated)), removed)

    def test_the_shipped_trust_root_pins_only_public_keys(self) -> None:
        shipped = json.loads((ROOT / "src" / "checkstead" / "snapshot_trust.json").read_text(encoding="utf-8"))
        text = json.dumps(shipped)
        self.assertNotIn("PRIVATE KEY", text)
        trust = load_trust(ROOT / "src" / "checkstead" / "snapshot_trust.json")
        self.assertTrue(any(key.status == "current" for key in trust.keys.values()))


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

    def test_the_updater_gates_publishing_on_a_canary_and_can_validate_only(self) -> None:
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        canary = script.index("CANARY_CVE=")
        self.assertLess(script.index("  --updateonly \\\n"), canary)
        self.assertLess(canary, script.index('gh release create "$TAG"'))
        self.assertIn('CANARY_JAR_SHA256="87363a4c94eaabeefd8b930cb059f66b64c9f7d632862f23de3012da7660047b"', script)
        self.assertIn("Refusing to publish. The canary scan", script)
        self.assertIn('cp -a "${WORK}/data" "${WORK}/canary/data"', script)
        validate = script.index('if [[ "$VALIDATE_ONLY" == "1" ]]; then\n  echo "Validation only.')
        self.assertLess(validate, script.index('gh release create "$TAG"'))
        workflow = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        self.assertIn("validate_only", workflow)
        self.assertIn("CHECKSTEAD_VALIDATE_ONLY", workflow)

    def test_the_job_summary_says_when_no_standby_key_is_pinned(self) -> None:
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        self.assertIn("No standby key is pinned", script)
        self.assertIn('k.status == "current" and i != os.environ["CHECKSTEAD_SNAPSHOT_KEY_ID"]', script)

    def test_the_signing_job_runs_in_a_protected_environment(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        self.assertIn("environment: snapshot-signing", workflow)
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        self.assertIn("--nvdValidForHours 0", script)
