"""Phase 1 proof: one snapshot per UTC day, and the scan client never calls NVD."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import zipfile
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, mock
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.engine import NVD_NOTICE, pinned_engine  # noqa: E402
from checkstead.errors import RefusedHost, SnapshotRefused  # noqa: E402
from checkstead.http import build_opener, download, read_text  # noqa: E402
from checkstead.scan import build_scan_command, run_scan, scrub_environment  # noqa: E402
from checkstead.snapshot import parse_manifest, safe_extract, write_manifest  # noqa: E402

PIN = "13.0.0"

# The shipped trust store pins the production key, so every unsigned snapshot
# is refused. Fixture snapshots are signed with a throwaway key, and the client
# (and every CLI subprocess) trusts only that key through CHECKSTEAD_SNAPSHOT_TRUST.
_TEST_TRUST = ROOT / "build" / "tests" / "trust" / "snapshot_trust.json"


def _test_signing_key() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from checkstead.snapshot_auth import public_pem_for

    private = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    _TEST_TRUST.parent.mkdir(parents=True, exist_ok=True)
    _TEST_TRUST.write_text(
        json.dumps(
            {"format": 1, "keys": [{"id": "test-fixtures", "status": "current", "publicKeyPem": public_pem_for(private)}]}
        ),
        encoding="utf-8",
    )
    os.environ["CHECKSTEAD_SNAPSHOT_TRUST"] = str(_TEST_TRUST)
    return private


TEST_SIGNING_KEY = _test_signing_key()


class FixtureServer:
    def __init__(self) -> None:
        self.manifest = b""
        self.zip_bytes = b""
        self.paths: list[str] = []
        self.hosts: list[str] = []
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._httpd.state = self
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def _handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                state = outer
                path = urlparse(self.path).path
                state.paths.append(path)
                state.hosts.append(self.headers.get("Host", ""))
                if path == "/manifest.json":
                    body = state.manifest
                elif path == "/checkstead-db.zip":
                    body = state.zip_bytes
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


def write_zip(path: Path, label: str) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("FIXTURE", f"checkstead test fixture {label}, not an NVD database\n")


def manifest_for(zip_path: Path, snapshot_time: str, engine: str = PIN, signed: bool = True) -> bytes:
    from checkstead.snapshot_auth import load_trust, sign_manifest

    payload = {
        "format": 1,
        "engineVersion": engine,
        "snapshotTime": snapshot_time,
        "checksum": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "database": "checkstead-db.zip",
    }
    if signed:
        payload = sign_manifest(payload, TEST_SIGNING_KEY, "test-fixtures", load_trust())
    return json.dumps(payload).encode("utf-8")


def fake_engine(path: Path) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "out=\n"
        "prev=\n"
        'for arg in "$@"; do\n'
        '  if [ "$prev" = "--out" ]; then\n'
        "    out=$arg\n"
        "  fi\n"
        "  prev=$arg\n"
        "done\n"
        'mkdir -p "$out"\n'
        "printf '%s\\n' \"$@\" > \"$out/engine-argv.txt\"\n"
        'if [ -n "${NVD_API_KEY:-}" ]; then\n'
        "  echo leaked > \"$out/leaked\"\n"
        "  exit 9\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def run_cli(args: list[str], env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "checkstead", *args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class Phase1Tests(TestCase):
    def test_pin_is_the_verified_release(self) -> None:
        root_pin = (ROOT / "engine.version").read_text(encoding="utf-8").strip()
        package_pin = (ROOT / "src" / "checkstead" / "engine.version").read_text(encoding="utf-8").strip()
        self.assertEqual(root_pin, PIN)
        self.assertEqual(package_pin, PIN)
        self.assertEqual(pinned_engine(), PIN)

    def test_license_notice_and_readme_are_complete(self) -> None:
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertGreater(len(license_text.splitlines()), 150)
        self.assertIn("Apache License", license_text)
        self.assertIn("Grant of Patent License", license_text)
        self.assertIn("no-charge", license_text)
        self.assertIn("royalty-free", license_text)
        self.assertNotIn("grant*d", license_text)
        self.assertNotIn("free of*charge", license_text)
        for name in ("NOTICE", "README.md"):
            self.assertIn(NVD_NOTICE, (ROOT / name).read_text(encoding="utf-8"))
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("security/advisories/new", security)
        self.assertIn("chethan.kumblekar@ascertra.com", security)
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("Signed-off-by", contributing)
        self.assertIn("private suppression", contributing.lower())
        conduct = (ROOT / "CODE_OF_CONDUCT.md").read_text(encoding="utf-8")
        self.assertIn("Contributor Covenant", conduct)
        self.assertIn("chethan.kumblekar@ascertra.com", conduct)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("0.1.0", changelog)
        self.assertIn("node_modules", changelog)
        architecture = (ROOT / "docs" / "architecture.md").read_text(encoding="utf-8")
        self.assertIn(NVD_NOTICE, architecture)
        self.assertIn("Direct · Production", architecture)
        self.assertIn("Transitive · Dev", architecture)
        self.assertIn("node_modules", architecture)
        self.assertIn("Sign in on this computer", architecture)
        self.assertIn("personal GitHub account", architecture)
        self.assertIn("Rerun", architecture)
        issues = ROOT / ".github" / "ISSUE_TEMPLATE"
        self.assertTrue((issues / "config.yml").is_file())
        self.assertTrue((issues / "bug_report.yml").is_file())
        self.assertTrue((issues / "feature_request.yml").is_file())
        self.assertIn("security/advisories/new", (issues / "config.yml").read_text(encoding="utf-8"))
        pull_request = (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
        self.assertIn("git commit -s", pull_request)
        self.assertIn("private suppression", pull_request.lower())

    def test_reserved_config_is_not_applied_and_scans_share_a_snapshot(self) -> None:
        root = ROOT / "build" / "tests" / "same-day"
        if root.exists():
            subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        scan_path = root / "project"
        scan_path.mkdir()
        (scan_path / "README").write_text("sample\n", encoding="utf-8")
        engine = root / "dependency-check.sh"
        fake_engine(engine)
        zip_a = root / "a.zip"
        zip_b = root / "b.zip"
        write_zip(zip_a, "morning")
        write_zip(zip_b, "evening")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(zip_a, "2026-10-06T01:02:03Z")
        server.zip_bytes = zip_a.read_bytes()
        rules = root / "rules.xml"
        rules.write_text(
            "<?xml version=\"1.0\"?>\n"
            "<suppressions>\n"
            "  <suppress until=\"2026-01-01\">\n"
            "    <notes>Expired before the scan day.</notes>\n"
            "    <cve>CVE-2020-0001</cve>\n"
            "  </suppress>\n"
            "</suppressions>\n",
            encoding="utf-8",
        )
        config = root / "checkstead.yml"
        config.write_text(
            "snapshot: " + server.manifest_url + "\n"
            "scorePolicy: prefer-newest\n"
            "threshold: 9\n"
            "privateSuppressions: rules.xml\n",
            encoding="utf-8",
        )
        cache = root / "cache"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["CHECKSTEAD_CACHE"] = str(cache)
        env["CHECKSTEAD_TODAY"] = "2026-10-06"
        env["NVD_API_KEY"] = "this-must-not-reach-the-engine"
        env["CHECKSTEAD_ENGINE"] = str(engine)
        reports = []
        for name in ("one", "two"):
            if name == "two":
                server.manifest = manifest_for(zip_b, "2026-10-06T18:00:00Z")
                server.zip_bytes = zip_b.read_bytes()
            out = root / name
            completed = run_cli(
                [
                    "scan",
                    "--scan",
                    str(scan_path),
                    "--config",
                    str(config),
                    "--out",
                    str(out),
                    "--cache",
                    str(cache),
                    "--project",
                    "sample",
                ],
                env,
                root,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            report = (out / "checkstead.txt").read_text(encoding="utf-8")
            reports.append(report)
            self.assertIn("engine: 13.0.0\n", report)
            self.assertIn("snapshot: 2026-10-06T01:02:03Z\n", report)
            self.assertIn(NVD_NOTICE, report)
            self.assertIn("score-policy: prefer-newest\n", report)
            self.assertIn("suppression-expired: CVE-2020-0001 until 2026-01-01\n", report)
            self.assertIn("suppression-unused: CVE-2020-0001\n", report)
            command = (out / "checkstead-command.txt").read_text(encoding="utf-8")
            self.assertIn("--noupdate\n", command)
            self.assertIn("--suppression\n", command)
            self.assertIn("rules.xml", command)
            self.assertNotIn("--nvdApiKey", command)
            self.assertNotIn("services.nvd.nist.gov", command)
            self.assertNotIn("failOnCVSS", command)
            self.assertNotIn("http://", command)
            self.assertNotIn("https://", command)
            self.assertFalse((out / "leaked").exists())
            argv = (out / "engine-argv.txt").read_text(encoding="utf-8")
            self.assertIn("--noupdate\n", argv)
            self.assertNotIn("nvdApiKey", argv)
            self.assertNotIn("services.nvd.nist.gov", argv)
        self.assertEqual(reports[0], reports[1])
        self.assertEqual(server.paths.count("/manifest.json"), 1)
        self.assertEqual(server.paths.count("/checkstead-db.zip"), 1)
        for host in server.hosts:
            self.assertNotIn("services.nvd.nist.gov", host)
        for path in server.paths:
            self.assertNotIn("services.nvd.nist.gov", path)

    def test_dry_run_does_not_start_the_engine(self) -> None:
        root = ROOT / "build" / "tests" / "dry-run"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        scan_path = root / "project"
        scan_path.mkdir()
        engine = root / "dependency-check.sh"
        engine.write_text("#!/bin/sh\ntouch \"$0.started\"\nexit 0\n", encoding="utf-8")
        engine.chmod(0o755)
        blob = root / "db.zip"
        write_zip(blob, "dry")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(blob, "2026-10-06T01:02:03Z")
        server.zip_bytes = blob.read_bytes()
        out = root / "out"
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["CHECKSTEAD_TODAY"] = "2026-10-06"
        env["NVD_API_KEY"] = "unused"
        completed = run_cli(
            [
                "scan",
                "--dry-run",
                "--scan",
                str(scan_path),
                "--out",
                str(out),
                "--cache",
                str(root / "cache"),
                "--engine",
                str(engine),
                "--config",
                str(self._config(root, server.manifest_url)),
            ],
            env,
            root,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("dry run", completed.stdout)
        self.assertIn("snapshot: 2026-10-06T01:02:03Z", completed.stdout)
        self.assertFalse((root / "dependency-check.sh.started").exists())
        for host in server.hosts:
            self.assertNotIn("services.nvd.nist.gov", host)

    def test_other_engine_is_refused_before_the_zip_or_the_scanner(self) -> None:
        root = ROOT / "build" / "tests" / "other-engine"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        scan_path = root / "project"
        scan_path.mkdir()
        engine = root / "dependency-check.sh"
        fake_engine(engine)
        blob = root / "db.zip"
        write_zip(blob, "old")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(blob, "2026-10-06T01:02:03Z", engine="12.1.8")
        server.zip_bytes = blob.read_bytes()
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["CHECKSTEAD_TODAY"] = "2026-10-06"
        completed = run_cli(
            [
                "scan",
                "--scan",
                str(scan_path),
                "--out",
                str(root / "out"),
                "--cache",
                str(root / "cache"),
                "--engine",
                str(engine),
                "--config",
                str(self._config(root, server.manifest_url)),
            ],
            env,
            root,
        )
        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("12.1.8", completed.stderr)
        self.assertIn(PIN, completed.stderr)
        self.assertNotIn("/checkstead-db.zip", server.paths)
        self.assertFalse((root / "out" / "engine-argv.txt").exists())

    def test_next_utc_day_can_take_a_newer_snapshot(self) -> None:
        root = ROOT / "build" / "tests" / "next-day"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        scan_path = root / "project"
        scan_path.mkdir()
        zip_a = root / "a.zip"
        zip_b = root / "b.zip"
        write_zip(zip_a, "day-one")
        write_zip(zip_b, "day-two")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(zip_a, "2026-10-06T01:02:03Z")
        server.zip_bytes = zip_a.read_bytes()
        first = run_scan(
            [scan_path],
            project="sample",
            config_snapshot_url=server.manifest_url,
            out_dir=root / "one",
            cache_dir=root / "cache",
            today=date(2026, 10, 6),
            dry_run=True,
        )
        server.manifest = manifest_for(zip_b, "2026-10-07T01:02:03Z")
        server.zip_bytes = zip_b.read_bytes()
        second = run_scan(
            [scan_path],
            project="sample",
            config_snapshot_url=server.manifest_url,
            out_dir=root / "two",
            cache_dir=root / "cache",
            today=date(2026, 10, 7),
            dry_run=True,
        )
        self.assertEqual(first.snapshot_time, "2026-10-06T01:02:03Z")
        self.assertEqual(second.snapshot_time, "2026-10-07T01:02:03Z")
        for host in server.hosts:
            self.assertNotIn("services.nvd.nist.gov", host)

    def test_https_opener_uses_certifi_and_still_refuses_nvd(self) -> None:
        import ssl
        import urllib.request

        import certifi

        bundle = Path(certifi.where())
        self.assertTrue(bundle.is_file())
        self.assertGreater(bundle.stat().st_size, 0)
        real_create = ssl.create_default_context
        contexts: list[ssl.SSLContext] = []

        def create_default_context(*args, **kwargs):
            self.assertEqual(args, ())
            self.assertEqual(kwargs, {"cafile": str(bundle)})
            context = real_create(*args, **kwargs)
            contexts.append(context)
            return context

        with mock.patch("checkstead.http.ssl.create_default_context", create_default_context):
            opener = build_opener()

        https = [
            handler
            for handler in opener.handlers
            if isinstance(handler, urllib.request.HTTPSHandler)
        ]
        self.assertEqual([handler._context for handler in https], contexts)
        with mock.patch.object(
            urllib.request.OpenerDirector,
            "open",
            side_effect=AssertionError("the client opened a connection"),
        ):
            with self.assertRaises(RefusedHost):
                read_text("https://services.nvd.nist.gov/rest/json/cves/2.0", opener)

    def test_nvd_host_is_refused_without_a_connection(self) -> None:
        dest = ROOT / "build" / "tests" / "blocked.bin"

        def fail_open(self, *args, **kwargs):
            raise AssertionError("the client opened a connection")

        with mock.patch("urllib.request.OpenerDirector.open", fail_open):
            with self.assertRaises(RefusedHost):
                download("https://services.nvd.nist.gov/rest/json/cves/2.0", dest)

    def test_redirect_to_nvd_is_refused(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://services.nvd.nist.gov/rest/json/cves/2.0")
                self.end_headers()

            def log_message(self, fmt, *args):
                return

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(httpd.server_close)
        host, port = httpd.server_address[:2]
        with self.assertRaises(RefusedHost):
            download(f"http://{host}:{port}/manifest.json", ROOT / "build" / "tests" / "redirect.bin")

    def test_checksum_mismatch_and_zip_slip_are_refused(self) -> None:
        root = ROOT / "build" / "tests" / "checksum"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        blob = root / "db.zip"
        write_zip(blob, "bad-sum")
        server = FixtureServer()
        self.addCleanup(server.close)
        payload = json.loads(manifest_for(blob, "2026-10-06T01:02:03Z"))
        payload["checksum"] = "0" * 64
        server.manifest = json.dumps(payload).encode("utf-8")
        server.zip_bytes = blob.read_bytes()
        scan_path = root / "project"
        scan_path.mkdir()
        with self.assertRaises(SnapshotRefused):
            run_scan(
                [scan_path],
                project="sample",
                config_snapshot_url=server.manifest_url,
                out_dir=root / "out",
                cache_dir=root / "cache",
                today=date(2026, 10, 6),
                dry_run=True,
            )
        slipped = root / "slipped.zip"
        with zipfile.ZipFile(slipped, "w") as archive:
            archive.writestr("../escape.txt", "nope\n")
        with self.assertRaises(SnapshotRefused):
            safe_extract(slipped, root / "data")
        self.assertFalse((root / "escape.txt").exists())
        linked = root / "linked.zip"
        info = zipfile.ZipInfo("escape-link")
        info.create_system = 3
        info.external_attr = (0o120777) << 16
        with zipfile.ZipFile(linked, "w") as archive:
            archive.writestr(info, b"../escape.txt")
        with self.assertRaises(SnapshotRefused):
            safe_extract(linked, root / "linked")
        self.assertFalse((root / "escape.txt").is_symlink())
        self.assertFalse((root / "linked" / "escape-link").exists())
        absolute = root / "absolute.zip"
        with zipfile.ZipFile(absolute, "w") as archive:
            archive.writestr("/tmp/checkstead-absolute.txt", "nope\n")
        with self.assertRaises(SnapshotRefused):
            safe_extract(absolute, root / "absolute")
        self.assertFalse(Path("/tmp/checkstead-absolute.txt").exists())

    def test_cached_zip_that_does_not_match_its_manifest_is_kept_and_refused(self) -> None:
        root = ROOT / "build" / "tests" / "stale-cache"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        day = root / "cache" / "2026-10-06"
        day.mkdir(parents=True)
        blob = day / "checkstead-db.zip"
        write_zip(blob, "cached")
        manifest = manifest_for(blob, "2026-10-06T01:02:03Z")
        blob.write_bytes(b"corrupted")
        (day / "manifest.json").write_bytes(manifest)
        scan_path = root / "project"
        scan_path.mkdir()
        with self.assertRaises(SnapshotRefused) as raised:
            run_scan(
                [scan_path],
                project="sample",
                config_snapshot_url="https://example.invalid/manifest.json",
                out_dir=root / "out",
                cache_dir=root / "cache",
                today=date(2026, 10, 6),
                dry_run=True,
            )
        self.assertIn("no longer matches", str(raised.exception))
        self.assertTrue((day / "manifest.json").is_file())
        self.assertEqual(blob.read_bytes(), b"corrupted")

    def test_cleartext_http_is_limited_to_loopback(self) -> None:
        from checkstead.http import ensure_allowed

        ensure_allowed("http://127.0.0.1:9/manifest.json")
        ensure_allowed("http://localhost/manifest.json")
        ensure_allowed("https://github.com/example/manifest.json")
        with self.assertRaises(RefusedHost):
            ensure_allowed("http://example.com/manifest.json")
        with self.assertRaises(RefusedHost):
            ensure_allowed("file:///tmp/manifest.json")
        with self.assertRaises(RefusedHost):
            ensure_allowed("https://services.nvd.nist.gov/rest/json/cves/2.0")
        with self.assertRaises(RefusedHost):
            ensure_allowed("https://user:password@github.com/manifest.json")
        with self.assertRaises(RefusedHost):
            ensure_allowed("https://169.254.169.254/latest/meta-data")
        with self.assertRaises(RefusedHost):
            ensure_allowed("https://[::ffff:169.254.169.254]/latest/meta-data")
        with self.assertRaises(RefusedHost):
            ensure_allowed("https://metadata.google.internal/computeMetadata/v1/")
        ensure_allowed("https://10.0.0.8/manifest.json")

    def test_doctor_prints_the_pin_and_hides_secret_values(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        env["NVD_API_KEY"] = "super-secret-key"
        env["CHECKSTEAD_GITHUB_CLIENT_SECRET"] = "another-secret"
        completed = subprocess.run(
            [sys.executable, "-m", "checkstead", "doctor"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("engine-pin: 13.0.0", completed.stdout)
        self.assertIn("nvd-api-key: set", completed.stdout)
        self.assertIn("CHECKSTEAD_GITHUB_CLIENT_SECRET: set", completed.stdout)
        self.assertNotIn("super-secret-key", completed.stdout + completed.stderr)
        self.assertNotIn("another-secret", completed.stdout + completed.stderr)

    def test_manifest_writer_records_the_pin_and_checksum(self) -> None:
        root = ROOT / "build" / "tests" / "manifest"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        blob = root / "checkstead-db.zip"
        write_zip(blob, "publish")
        manifest = write_manifest(blob, root / "manifest.json")
        self.assertEqual(manifest["engineVersion"], PIN)
        self.assertEqual(manifest["checksum"], hashlib.sha256(blob.read_bytes()).hexdigest())
        parsed = parse_manifest((root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(parsed["engineVersion"], PIN)
        payload = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        for name in ("http:evil", "../escape.zip", "zip?x=1", "a/b.zip", ""):
            forged = dict(payload)
            forged["database"] = name
            with self.assertRaises(SnapshotRefused):
                parse_manifest(json.dumps(forged))

    def test_scan_environment_drops_the_api_key(self) -> None:
        cleaned = scrub_environment({"PATH": "/usr/bin", "NVD_API_KEY": "secret", "NVD_APIKEY": "secret"})
        self.assertEqual(cleaned, {"PATH": "/usr/bin"})
        command = build_scan_command(
            Path("/opt/dependency-check/bin/dependency-check.sh"),
            Path("/var/cache/checkstead/data"),
            [Path("/work/project")],
            "sample",
            Path("/work/out"),
        )
        joined = "\n".join(command)
        self.assertIn("--noupdate", command)
        self.assertNotIn("--nvdApiKey", command)
        self.assertNotIn("--updateonly", command)
        self.assertNotIn("services.nvd.nist.gov", joined)

    def test_yarn_audit_is_disabled_only_when_yarn_does_not_run(self) -> None:
        root = ROOT / "build" / "tests" / "yarn-audit"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        engine = Path("/opt/dependency-check/bin/dependency-check.sh")
        data = Path("/var/cache/checkstead/data")
        scan = Path("/work/project")
        out = Path("/work/out")

        def command_with(path: Path) -> list[str]:
            with mock.patch.dict(os.environ, {"PATH": str(path)}, clear=False):
                return build_scan_command(engine, data, [scan], "sample", out, dict(os.environ))

        missing = root / "missing"
        missing.mkdir()
        without = command_with(missing)
        self.assertIn("--disableYarnAudit", without)
        self.assertNotIn("nvdApiKey", without)
        self.assertNotIn("--disableNodeAudit", without)

        inert = root / "inert"
        inert.mkdir()
        yarn = inert / "yarn"
        yarn.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        yarn.chmod(0o644)
        self.assertIn("--disableYarnAudit", command_with(inert))

        failing = root / "failing"
        broken = failing / "yarn"
        broken.parent.mkdir()
        broken.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        broken.chmod(0o755)
        self.assertIn("--disableYarnAudit", command_with(failing))

        blank = root / "blank"
        empty = blank / "yarn"
        empty.parent.mkdir()
        empty.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        empty.chmod(0o755)
        self.assertIn("--disableYarnAudit", command_with(blank))

        working = root / "working"
        ok = working / "yarn"
        ok.parent.mkdir()
        ok.write_text("#!/bin/sh\necho 1.22.22\n", encoding="utf-8")
        ok.chmod(0o755)
        enabled = command_with(working)
        self.assertNotIn("--disableYarnAudit", enabled)
        self.assertIn("--noupdate", enabled)

    def test_updater_stops_without_a_key_and_keeps_the_days_snapshot(self) -> None:
        env = os.environ.copy()
        env["NVD_API_KEY"] = ""
        missing = subprocess.run(
            ["bash", str(ROOT / "scripts" / "update-snapshot.sh")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(missing.returncode, 1, missing.stdout + missing.stderr)
        self.assertIn("NVD_API_KEY", missing.stderr)
        self.assertIn("stand-in database", missing.stderr)

        stub = ROOT / "build" / "tests" / "gh-stub"
        subprocess.run(["rm", "-rf", str(stub)], check=True)
        stub.mkdir(parents=True)
        log = stub / "calls.log"
        for name in ("gh", "curl", "wget"):
            tool = stub / name
            tool.write_text(
                "#!/bin/sh\n"
                f"printf '%s' {name} >> \"$STUB_LOG\"\n"
                "printf ' %s' \"$@\" >> \"$STUB_LOG\"\n"
                "printf '\\n' >> \"$STUB_LOG\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            tool.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        env["NVD_API_KEY"] = "not-a-real-key"
        env["STUB_LOG"] = str(log)
        kept = subprocess.run(
            ["bash", str(ROOT / "scripts" / "update-snapshot.sh")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(kept.returncode, 0, kept.stderr)
        self.assertIn("already published", kept.stdout)
        calls = log.read_text(encoding="utf-8")
        self.assertIn("gh release view", calls)
        self.assertNotIn("curl", calls)
        self.assertNotIn("not-a-real-key", calls)

    def test_publish_wiring_uses_the_secret_and_the_action_calls_scan(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "update-snapshot.sh").read_text(encoding="utf-8")
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        gradle = (ROOT / "integrations" / "gradle" / "checkstead.gradle").read_text(encoding="utf-8")
        entry = (ROOT / "scripts" / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn("secrets.NVD_API_KEY", workflow)
        self.assertIn("--updateonly", script)
        self.assertIn("--nvdApiKey", script)
        self.assertNotIn("services.nvd.nist.gov", script)
        self.assertNotRegex(script, r"NVD_API_KEY=[A-Za-z0-9]")
        self.assertNotIn("NVD_API_KEY", action)
        self.assertNotIn("nvdApiKey", action)
        self.assertRegex(
            action,
            r"uses: github/codeql-action/upload-sarif@[0-9a-f]{40} # v\d",
        )
        self.assertIn("${{ inputs.output }}/checkstead.sarif", action)
        self.assertNotIn("services.nvd.nist.gov", action)
        self.assertIn("checkstead", entry)
        self.assertIn("scan", gradle)
        self.assertIn("checkstead", gradle)
        self.assertNotIn("nvdApiKey", gradle)
        config = (ROOT / "checkstead.yml").read_text(encoding="utf-8")
        for key in ("snapshot:", "scorePolicy:", "threshold:", "privateSuppressions:"):
            self.assertIn(key, config)
        snapshot = (
            "https://github.com/chethankumblekar/dependency-check-db-cache"
            "/releases/latest/download/manifest.json"
        )
        self.assertIn(f"snapshot: {snapshot}", config)
        self.assertNotIn("github.com/chethankumblekar/checkstead/", config)
        defaults = (ROOT / "src" / "checkstead" / "config.py").read_text(encoding="utf-8")
        self.assertIn(snapshot, defaults)
        self.assertNotIn("github.com/chethankumblekar/checkstead/", defaults)
        self.assertIn("\n  --latest \\\n", script)
        self.assertIn("Refusing to publish. The manifest checksum does not match the zip.", script)
        self.assertFalse((ROOT / ".github" / "workflows" / "update-db.yml").exists())
        updater = (ROOT / ".github" / "workflows" / "update-snapshot.yml").read_text(encoding="utf-8")
        self.assertNotIn("12.1.8", updater)
        self.assertNotIn("12.1.8", script)

    def _config(self, root: Path, url: str) -> Path:
        path = root / "checkstead.yml"
        path.write_text(
            f"snapshot: {url}\nscorePolicy:\nthreshold:\nprivateSuppressions:\n",
            encoding="utf-8",
        )
        return path
