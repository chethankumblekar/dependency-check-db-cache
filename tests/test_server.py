"""The server accepts a provider token and lets an administrator manage accounts."""

from __future__ import annotations

import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.ui import bind_server  # noqa: E402


def fetch_github(url: str, headers: dict[str, str]) -> dict:
    token = headers.get("Authorization")
    if token == "Bearer ghp_example":
        return {"login": "octocat", "id": 7, "name": "The Octocat"}
    if token == "Bearer ghp_ada":
        return {"login": "ada", "id": 8, "name": "Ada"}
    raise AssertionError("unexpected token")


class ServerTests(TestCase):
    def setUp(self) -> None:
        data = ROOT / "build" / "tests" / "server" / self.id().split(".")[-1]
        if data.exists():
            import shutil
            shutil.rmtree(data)
        self.server = bind_server(ROOT / "ui" / "scans", "127.0.0.1", 0, data, fetch_github)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"

    def request(self, path: str, method: str = "GET", body: dict | None = None, cookie: str | None = None):
        data = None if body is None else json.dumps(body).encode()
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = f"checkstead_session={cookie}"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                raw = response.read().decode()
                return response.status, json.loads(raw) if raw else {}, response.headers.get("Set-Cookie")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            return exc.code, json.loads(raw) if raw else {}, None

    def test_sign_in_then_add_a_user(self) -> None:
        providers = self.request("/api/providers")[1]
        self.assertEqual(
            [item["key"] for item in providers["providers"]],
            ["github", "azure-devops", "entra"],
        )
        self.assertTrue(providers["providers"][2]["sso"])
        self.assertNotIn("gitlab", [item["key"] for item in providers["providers"]])
        self.assertIn("GitLab", providers["later"])

        status, payload, cookie = self.request(
            "/api/session",
            "POST",
            {"provider": "github", "token": "ghp_example"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["user"]["role"], "admin")
        self.assertNotIn("ghp_example", json.dumps(payload))
        self.assertIn("checkstead_session=", cookie)
        session = cookie.split(";", 1)[0].split("=", 1)[1]

        status, added, _cookie = self.request(
            "/api/admin/users",
            "POST",
            {"provider": "github", "login": "ada", "role": "user"},
            session,
        )
        self.assertEqual(status, 201, added)
        status, listing, _cookie = self.request("/api/admin/users", cookie=session)
        self.assertEqual(
            [(user["login"], user["role"]) for user in listing["users"]],
            [("octocat", "admin"), ("ada", "user")],
        )
        ada = listing["users"][1]["id"]
        status, changed, _cookie = self.request(
            f"/api/admin/users/{ada}",
            "PATCH",
            {"role": "admin"},
            session,
        )
        self.assertEqual(changed["user"]["role"], "admin")
        status, _gone, _cookie = self.request(f"/api/admin/users/{ada}", "DELETE", cookie=session)
        self.assertEqual(status, 200)
        self.assertEqual(len(self.request("/api/admin/users", cookie=session)[1]["users"]), 1)
        owner = self.request("/api/admin/users", cookie=session)[1]["users"][0]["id"]
        status, blocked, _cookie = self.request(
            f"/api/admin/users/{owner}",
            "DELETE",
            cookie=session,
        )
        self.assertEqual(status, 409, blocked)

    def test_a_user_can_read_the_timeline_and_cannot_administer(self) -> None:
        _status, _payload, cookie = self.request(
            "/api/session",
            "POST",
            {"provider": "github", "token": "ghp_example"},
        )
        session = cookie.split(";", 1)[0].split("=", 1)[1]
        self.request(
            "/api/admin/users",
            "POST",
            {"provider": "github", "login": "ada", "role": "user"},
            session,
        )
        self.request("/api/session", "DELETE", cookie=session)
        status, payload, cookie = self.request(
            "/api/session",
            "POST",
            {"provider": "github", "token": "ghp_ada"},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["user"]["role"], "user")
        ada_session = cookie.split(";", 1)[0].split("=", 1)[1]
        status, history, _cookie = self.request("/api/history", cookie=ada_session)
        self.assertEqual(status, 200)
        self.assertIn("drifts", history)
        status, denied, _cookie = self.request("/api/admin/users", cookie=ada_session)
        self.assertEqual(status, 403, denied)
