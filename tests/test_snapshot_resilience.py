"""Retries, redirect credentials, size limits, and snapshot rollback."""

from __future__ import annotations

import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from checkstead import http as http_module  # noqa: E402
from checkstead.archive import ArchiveRejected, safe_extract  # noqa: E402
from checkstead.errors import RefusedHost, SnapshotRefused  # noqa: E402
from checkstead.http import download, read_text, with_retries  # noqa: E402
from checkstead.snapshot import resolve_snapshot  # noqa: E402
from test_phase1 import FixtureServer, manifest_for, write_zip  # noqa: E402


class FlakyServer:
    """Answers 503 a set number of times, then 200. Records Authorization headers."""

    def __init__(self, failures: int, body: bytes = b"{}", redirect_to: str | None = None) -> None:
        self.failures = failures
        self.body = body
        self.redirect_to = redirect_to
        self.calls = 0
        self.authorization: list[str | None] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.calls += 1
                outer.authorization.append(self.headers.get("Authorization"))
                if outer.redirect_to and self.path == "/start":
                    self.send_response(302)
                    self.send_header("Location", outer.redirect_to)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if outer.failures > 0:
                    outer.failures -= 1
                    self.send_error(503)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, fmt, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def url(self, host: str = "127.0.0.1", path: str = "/file") -> str:
        return f"http://{host}:{self.httpd.server_address[1]}{path}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


class RetryTests(TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(http_module.time, "sleep")
        self.sleep = patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_transient_503_is_retried(self) -> None:
        server = FlakyServer(failures=2, body=b'{"ok": true}')
        self.addCleanup(server.close)
        self.assertEqual(read_text(server.url()), '{"ok": true}')
        self.assertEqual(server.calls, 3)
        self.assertEqual([call.args[0] for call in self.sleep.call_args_list], [1, 2])

    def test_retries_stop_and_the_last_error_is_raised(self) -> None:
        server = FlakyServer(failures=99)
        self.addCleanup(server.close)
        with self.assertRaises(urllib.error.HTTPError) as caught:
            read_text(server.url())
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(server.calls, 4)

    def test_a_404_is_not_retried(self) -> None:
        calls = []

        def missing():
            calls.append(1)
            raise urllib.error.HTTPError("https://example.invalid", 404, "Not Found", {}, None)

        with self.assertRaises(urllib.error.HTTPError):
            with_retries(missing, "test")
        self.assertEqual(len(calls), 1)

    def test_a_refused_host_is_not_retried(self) -> None:
        calls = []

        def refused():
            calls.append(1)
            raise RefusedHost("no")

        with self.assertRaises(RefusedHost):
            with_retries(refused, "test")
        self.assertEqual(len(calls), 1)

    def test_a_download_retries_and_leaves_no_partial_file(self) -> None:
        server = FlakyServer(failures=1, body=b"zip-bytes")
        self.addCleanup(server.close)
        dest = ROOT / "build" / "tests" / "retry-download" / "file.zip"
        shutil.rmtree(dest.parent, ignore_errors=True)
        download(server.url(), dest)
        self.assertEqual(dest.read_bytes(), b"zip-bytes")
        self.assertFalse(dest.with_suffix(".zip.partial").exists())

    def test_an_oversized_text_response_is_refused(self) -> None:
        server = FlakyServer(failures=0, body=b"x" * (http_module.MAX_TEXT_BYTES + 10))
        self.addCleanup(server.close)
        with self.assertRaises(RefusedHost):
            read_text(server.url())


class RedirectCredentialTests(TestCase):
    def test_authorization_is_dropped_when_the_redirect_changes_host(self) -> None:
        target = FlakyServer(failures=0, body=b"payload")
        self.addCleanup(target.close)
        # localhost and 127.0.0.1 are different host names for the same server.
        origin = FlakyServer(failures=0, redirect_to=target.url("localhost"))
        self.addCleanup(origin.close)
        dest = ROOT / "build" / "tests" / "redirect-auth" / "repo.zip"
        shutil.rmtree(dest.parent, ignore_errors=True)
        download(origin.url(path="/start"), dest, headers={"Authorization": "Bearer secret"})
        self.assertEqual(origin.authorization, ["Bearer secret"])
        self.assertEqual(target.authorization, [None])
        self.assertEqual(dest.read_bytes(), b"payload")

    def test_authorization_is_kept_on_the_same_host(self) -> None:
        server = FlakyServer(failures=0, body=b"payload")
        self.addCleanup(server.close)
        server.redirect_to = server.url(path="/file")
        dest = ROOT / "build" / "tests" / "redirect-same" / "repo.zip"
        shutil.rmtree(dest.parent, ignore_errors=True)
        download(server.url(path="/start"), dest, headers={"Authorization": "Bearer secret"})
        self.assertEqual(server.authorization, ["Bearer secret", "Bearer secret"])


class ArchiveLimitTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "archive-limits" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)

    def test_a_zip_bomb_is_refused_before_writing(self) -> None:
        bomb = self.root / "bomb.zip"
        with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("big", b"\0" * (4 * 1024 * 1024))
        with mock.patch.dict(os.environ, {"CHECKSTEAD_MAX_ARCHIVE_BYTES": str(1024 * 1024)}):
            with self.assertRaises(ArchiveRejected) as caught:
                safe_extract(bomb, self.root / "out")
        self.assertIn("CHECKSTEAD_MAX_ARCHIVE_BYTES", str(caught.exception))
        self.assertFalse((self.root / "out" / "big").exists())

    def test_too_many_members_are_refused(self) -> None:
        many = self.root / "many.zip"
        with zipfile.ZipFile(many, "w") as archive:
            for index in range(20):
                archive.writestr(f"f{index}", b"x")
        with mock.patch.dict(os.environ, {"CHECKSTEAD_MAX_ARCHIVE_MEMBERS": "10"}):
            with self.assertRaises(ArchiveRejected):
                safe_extract(many, self.root / "out")

    def test_a_normal_archive_still_extracts(self) -> None:
        normal = self.root / "normal.zip"
        with zipfile.ZipFile(normal, "w") as archive:
            archive.writestr("dir/file.txt", b"hello")
        safe_extract(normal, self.root / "out")
        self.assertEqual((self.root / "out" / "dir" / "file.txt").read_bytes(), b"hello")


class RollbackTests(TestCase):
    def setUp(self) -> None:
        self.root = ROOT / "build" / "tests" / "rollback" / self.id().split(".")[-1]
        shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)
        self.server = FixtureServer()
        self.addCleanup(self.server.close)
        os.environ.pop("CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK", None)

    def publish(self, label: str, moment: str) -> None:
        archive = self.root / f"{label}.zip"
        write_zip(archive, label)
        self.server.manifest = manifest_for(archive, moment)
        self.server.zip_bytes = archive.read_bytes()

    def resolve(self, day: date):
        return resolve_snapshot(self.server.manifest_url, self.root / "cache", day)

    def test_an_older_snapshot_after_a_newer_one_is_refused(self) -> None:
        self.publish("new", "2026-10-07T01:00:00Z")
        self.assertEqual(self.resolve(date(2026, 10, 7)).snapshot_time, "2026-10-07T01:00:00Z")
        self.publish("old", "2026-10-05T01:00:00Z")
        with self.assertRaises(SnapshotRefused) as caught:
            self.resolve(date(2026, 10, 8))
        self.assertIn("CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK", str(caught.exception))

    def test_an_operator_can_accept_a_deliberate_rollback(self) -> None:
        self.publish("new", "2026-10-07T01:00:00Z")
        self.resolve(date(2026, 10, 7))
        self.publish("old", "2026-10-05T01:00:00Z")
        with mock.patch.dict(os.environ, {"CHECKSTEAD_ALLOW_SNAPSHOT_ROLLBACK": "1"}):
            self.assertEqual(self.resolve(date(2026, 10, 8)).snapshot_time, "2026-10-05T01:00:00Z")
        # The newest seen is still the later one.
        self.assertEqual(
            (self.root / "cache" / "newest-snapshot").read_text(encoding="utf-8").strip(),
            "2026-10-07T01:00:00Z",
        )

    def test_the_same_snapshot_on_a_later_day_is_accepted(self) -> None:
        self.publish("same", "2026-10-07T01:00:00Z")
        self.resolve(date(2026, 10, 7))
        self.assertEqual(self.resolve(date(2026, 10, 8)).snapshot_time, "2026-10-07T01:00:00Z")
