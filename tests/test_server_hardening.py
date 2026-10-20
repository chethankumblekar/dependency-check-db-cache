"""Host, Origin, and administrator checks on the timeline server."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import sys
import threading
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead import ui  # noqa: E402
from checkstead.ui import bind_server, host_allowed, origin_allowed  # noqa: E402

ENV_NAMES = (
    "CHECKSTEAD_LOCAL",
    "CHECKSTEAD_PUBLIC_BASE",
    "CHECKSTEAD_ALLOWED_HOSTS",
    "CHECKSTEAD_COOKIE_SECURE",
)


class HostAndOriginRules(TestCase):
    def setUp(self) -> None:
        saved = {name: os.environ.pop(name, None) for name in ENV_NAMES}

        def restore() -> None:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)

    def test_loopback_names_are_allowed_and_others_are_not(self) -> None:
        for host in ("127.0.0.1:8765", "localhost:8765", "[::1]:8765", "LOCALHOST", "localhost."):
            self.assertTrue(host_allowed(host), host)
        for host in ("", "evil.example", "evil.example:8765", "127.0.0.1.evil.example", "a b", "x@127.0.0.1"):
            self.assertFalse(host_allowed(host), host)

    def test_public_base_and_allowed_hosts_extend_the_list(self) -> None:
        os.environ["CHECKSTEAD_PUBLIC_BASE"] = "https://checkstead.example"
        os.environ["CHECKSTEAD_ALLOWED_HOSTS"] = "internal.example, 10.0.0.5"
        self.assertTrue(host_allowed("checkstead.example"))
        self.assertTrue(host_allowed("internal.example:8765"))
        self.assertTrue(host_allowed("10.0.0.5:8765"))
        self.assertFalse(host_allowed("other.example"))

    def test_origin_must_match_host(self) -> None:
        self.assertTrue(origin_allowed("http://127.0.0.1:8765", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("http://evil.example", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("http://127.0.0.1:9999", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("null", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("file://", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("", "127.0.0.1:8765", "cross-site"))
        self.assertFalse(origin_allowed("", "127.0.0.1:8765", "same-site"))
        self.assertTrue(origin_allowed("", "127.0.0.1:8765", "same-origin"))
        # curl and other non-browser clients send neither header.
        self.assertTrue(origin_allowed("", "127.0.0.1:8765"))

    def test_public_origin_is_accepted_when_a_proxy_rewrites_host(self) -> None:
        os.environ["CHECKSTEAD_PUBLIC_BASE"] = "https://checkstead.example"
        self.assertTrue(origin_allowed("https://checkstead.example", "127.0.0.1:8765"))
        self.assertFalse(origin_allowed("http://checkstead.example", "127.0.0.1:8765"))


class ServerGuards(TestCase):
    def setUp(self) -> None:
        saved = {name: os.environ.pop(name, None) for name in ENV_NAMES}

        def restore() -> None:
            for name, value in saved.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value

        self.addCleanup(restore)
        data = ROOT / "build" / "tests" / "server-hardening" / self.id().split(".")[-1]
        if data.exists():
            shutil.rmtree(data)
        self.started = threading.Event()
        self.release = threading.Event()

        def slow_scan(*_args, **_kwargs):
            self.started.set()
            self.release.wait(10)
            return []

        self.server = bind_server(ROOT / "ui" / "scans", "127.0.0.1", 0, data)
        self.slow_scan = slow_scan
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]

    def call(self, method: str, path: str, headers: dict[str, str] | None = None, body: bytes | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            connection.putrequest(method, path, skip_host=True)
            sent = {"Host": f"127.0.0.1:{self.port}"}
            sent.update(headers or {})
            for name, value in sent.items():
                connection.putheader(name, value)
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, response.read(), response.headers
        finally:
            connection.close()

    def test_a_rebinding_host_name_is_refused(self) -> None:
        status, body, _ = self.call("GET", "/api/history", {"Host": "attacker.example"})
        self.assertEqual(status, 421)
        self.assertIn(b"CHECKSTEAD_ALLOWED_HOSTS", body)
        status, _, _ = self.call(
            "POST", "/api/session/local", {"Host": f"attacker.example:{self.port}"}, b"{}"
        )
        self.assertEqual(status, 421)

    def test_health_answers_any_host_for_probes(self) -> None:
        status, body, _ = self.call("GET", "/api/health", {"Host": "checkstead-server:8765"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"ok": True})

    def test_a_cross_site_post_cannot_mint_the_local_session(self) -> None:
        status, _, headers = self.call(
            "POST", "/api/session/local", {"Origin": "https://attacker.example"}, b"{}"
        )
        self.assertEqual(status, 403)
        self.assertIsNone(headers.get("Set-Cookie"))
        status, _, _ = self.call(
            "POST", "/api/session/local", {"Sec-Fetch-Site": "cross-site"}, b"{}"
        )
        self.assertEqual(status, 403)
        status, _, headers = self.call(
            "POST", "/api/session/local", {"Origin": f"http://127.0.0.1:{self.port}"}, b"{}"
        )
        self.assertEqual(status, 200)
        self.assertIn("checkstead_session=", headers.get("Set-Cookie", ""))

    def test_a_cross_site_form_cannot_start_a_scan_or_a_github_app(self) -> None:
        for path in ("/api/github/scan", "/api/github/manifest", "/api/github/rerun"):
            status, _, _ = self.call(
                "POST",
                path,
                {"Origin": "null", "Content-Type": "application/x-www-form-urlencoded"},
                b"login=acme",
            )
            self.assertEqual(status, 403, path)

    def test_github_administration_needs_a_session_behind_a_proxy(self) -> None:
        status, _, _ = self.call("GET", "/api/github")
        self.assertEqual(status, 200)
        for mode in ("0", "1"):
            os.environ["CHECKSTEAD_LOCAL"] = mode
            status, _, _ = self.call("GET", "/api/github")
            self.assertEqual(status, 401, mode)
            status, _, _ = self.call("GET", "/github")
            self.assertEqual(status, 401, mode)

    def test_security_headers(self) -> None:
        status, _, headers = self.call("GET", "/")
        self.assertEqual(status, 200)
        policy = headers.get("Content-Security-Policy", "")
        self.assertIn("default-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("form-action 'self' https://github.com", policy)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIsNone(headers.get("Strict-Transport-Security"))
        os.environ["CHECKSTEAD_COOKIE_SECURE"] = "1"
        _, _, headers = self.call("GET", "/")
        self.assertIn("max-age=", headers.get("Strict-Transport-Security", ""))

    def test_a_second_scan_is_refused_while_one_runs(self) -> None:
        results: list[int] = []

        def first() -> None:
            results.append(self.call("POST", "/api/github/scan", {"Accept": "application/json"}, b"")[0])

        with mock.patch.object(ui, "scan_installed_repositories", self.slow_scan):
            worker = threading.Thread(target=first)
            worker.start()
            self.assertTrue(self.started.wait(10))
            status, body, _ = self.call("POST", "/api/github/scan", {"Accept": "application/json"}, b"")
            self.assertEqual(status, 409)
            self.assertIn("already running", json.loads(body)["error"])
            self.release.set()
            worker.join(10)
        self.assertEqual(results, [200])

    def test_a_stalled_client_is_dropped(self) -> None:
        self.assertEqual(self.server.RequestHandlerClass.timeout, ui.SOCKET_TIMEOUT_SECONDS)
        self.assertLessEqual(ui.SOCKET_TIMEOUT_SECONDS, 60)


class ConnectionHandlingTests(TestCase):
    def setUp(self) -> None:
        self.saved = os.environ.get("CHECKSTEAD_MAX_CONNECTIONS")
        os.environ["CHECKSTEAD_MAX_CONNECTIONS"] = "3"
        data = ROOT / "build" / "tests" / "server-connections" / self.id().split(".")[-1]
        if data.exists():
            shutil.rmtree(data)
        self.server = bind_server(ROOT / "ui" / "scans", "127.0.0.1", 0, data)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]

    def tearDown(self) -> None:
        if self.saved is None:
            os.environ.pop("CHECKSTEAD_MAX_CONNECTIONS", None)
        else:
            os.environ["CHECKSTEAD_MAX_CONNECTIONS"] = self.saved

    def test_one_connection_serves_several_requests(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            for _ in range(3):
                connection.request("GET", "/api/health")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.version, 11)
                response.read()
        finally:
            connection.close()

    def test_connections_past_the_limit_get_503_and_the_server_recovers(self) -> None:
        import socket
        import time

        self.assertEqual(self.server.max_connections, 3)
        held = []
        for _ in range(3):
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=5)
            sock.sendall(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            held.append(sock)
        time.sleep(0.3)
        status, _, headers = ServerGuards.call(self, "GET", "/api/health")
        self.assertEqual(status, 503)
        self.assertEqual(headers.get("Retry-After"), "1")
        for sock in held:
            sock.close()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status, _, _ = ServerGuards.call(self, "GET", "/api/health")
            if status == 200:
                break
            time.sleep(0.2)
        self.assertEqual(status, 200)

    def test_redirects_carry_a_length_so_keep_alive_does_not_hang(self) -> None:
        os.environ["CHECKSTEAD_GITHUB_CLIENT_ID"] = "id"
        os.environ["CHECKSTEAD_GITHUB_CLIENT_SECRET"] = "secret"
        try:
            status, body, headers = ServerGuards.call(self, "GET", "/api/sso/github/start")
        finally:
            os.environ.pop("CHECKSTEAD_GITHUB_CLIENT_ID", None)
            os.environ.pop("CHECKSTEAD_GITHUB_CLIENT_SECRET", None)
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Content-Length"), "0")
