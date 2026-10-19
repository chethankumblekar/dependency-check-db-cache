"""Commit authors come from git. GitHub and Entra sign-in exchange a code and drop it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.commit import lookup_branch, lookup_commit  # noqa: E402
from checkstead.ui import _local_sign_in, bind_server  # noqa: E402


class NoRedirect(urllib.request.HTTPErrorProcessor):
    def http_response(self, request, response):
        return response

    https_response = http_response


class Provider(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/user":
            self._json({"login": "octocat", "id": 7, "name": "The Octocat"})
            return
        if path == "/userinfo":
            self._json(
                {
                    "sub": "entra-1",
                    "oid": "entra-1",
                    "name": "Ada Admin",
                    "preferred_username": "ada@contoso.com",
                }
            )
            return
        if path == "/orgs/example/members/octocat":
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.server.posted = body  # type: ignore[attr-defined]
        self._json({"access_token": "from-provider", "token_type": "Bearer"})

    def _json(self, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        return


class CommitTests(TestCase):
    def test_git_names_the_author_and_an_unknown_revision_does_not(self) -> None:
        repo = ROOT / "build" / "tests" / "commit-author"
        if repo.exists():
            import shutil
            shutil.rmtree(repo)
        repo.mkdir(parents=True)
        env = os.environ.copy()
        env.update(
            {
                "GIT_AUTHOR_NAME": "Ada Lovelace",
                "GIT_AUTHOR_EMAIL": "ada@example.com",
                "GIT_COMMITTER_NAME": "Ada Lovelace",
                "GIT_COMMITTER_EMAIL": "ada@example.com",
            }
        )
        (repo / "note").write_text("tree\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "note"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "note"], cwd=repo, check=True, capture_output=True, env=env)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        self.assertEqual(lookup_commit(revision, repo), ("Ada Lovelace", "ada@example.com"))
        self.assertIsNone(lookup_commit("0" * 40, repo))
        current = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo, text=True
        ).strip()
        self.assertEqual(lookup_branch(repo), current)
        subprocess.run(["git", "checkout", "-b", "feature"], cwd=repo, check=True, capture_output=True)
        self.assertEqual(lookup_branch(repo), "feature")
        seen: list[list[str]] = []

        def fake_run(args, **_kwargs):
            seen.append(list(args))

            class _Completed:
                returncode = 0
                stdout = "Ada Lovelace\x00ada@example.com\n"

            return _Completed()

        import checkstead.commit as commit_module

        original = commit_module.subprocess.run
        commit_module.subprocess.run = fake_run
        try:
            self.assertEqual(lookup_commit(revision, repo), ("Ada Lovelace", "ada@example.com"))
        finally:
            commit_module.subprocess.run = original
        self.assertIn("safe.directory=*", seen[0])
        self.assertIn(f"safe.directory={repo}", seen[0])


class SsoTests(TestCase):
    def setUp(self) -> None:
        self._saved = {
            key: os.environ.get(key)
            for key in (
                "CHECKSTEAD_GITHUB_CLIENT_ID",
                "CHECKSTEAD_GITHUB_CLIENT_SECRET",
                "CHECKSTEAD_GITHUB_OAUTH",
                "CHECKSTEAD_GITHUB_API",
                "CHECKSTEAD_GITHUB_ORG",
                "CHECKSTEAD_ENTRA_CLIENT_ID",
                "CHECKSTEAD_ENTRA_CLIENT_SECRET",
                "CHECKSTEAD_ENTRA_AUTHORIZE",
                "CHECKSTEAD_ENTRA_TOKEN",
                "CHECKSTEAD_ENTRA_USERINFO",
            )
        }
        for key in self._saved:
            os.environ.pop(key, None)
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(provider.shutdown)
        self.addCleanup(provider.server_close)
        host, port = provider.server_address[:2]
        self.provider = f"http://{host}:{port}"
        data = ROOT / "build" / "tests" / "sso" / self.id().split(".")[-1]
        if data.exists():
            import shutil
            shutil.rmtree(data)
        server = bind_server(ROOT / "ui" / "scans", "127.0.0.1", 0, data)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        self.base = f"http://{host}:{port}"
        self.opener = urllib.request.build_opener(NoRedirect)

    def tearDown(self) -> None:
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def open(self, path: str, cookie: str | None = None):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(self.base + path, headers=headers)
        with self.opener.open(request) as response:
            return response.status, response.read(), response.headers

    def test_localhost_sign_in_opens_the_timeline_without_oauth(self) -> None:
        os.environ.pop("CHECKSTEAD_LOCAL", None)
        status, body, _headers = self.open("/")
        self.assertEqual(status, 200)
        self.assertIn(b"Sign in on this computer", body)
        self.assertIn(b'id="sign-in-local"', body)
        self.assertNotIn(b'id="local-sign-in" hidden', body)
        self.assertNotIn(b"need an app registration", body)
        self.assertIn(b"An OAuth app only signs a person in.", body)
        self.assertIn(b"reads and scans repositories.", body)
        self.assertNotIn(b'name="token"', body)
        self.assertNotIn(b"paste", body.lower())
        status, body, _headers = self.open("/api/sso")
        payload = json.loads(body)
        self.assertFalse(payload["github"]["enabled"])
        self.assertFalse(payload["entra"]["enabled"])
        self.assertTrue(payload["local"]["enabled"])
        request = urllib.request.Request(self.base + "/api/session/local", data=b"{}", method="POST")
        with self.opener.open(request) as response:
            signed = json.load(response)
            cookie = response.headers.get("Set-Cookie")
        self.assertEqual(signed["user"]["provider"], "local")
        self.assertEqual(signed["user"]["login"], "local")
        self.assertEqual(signed["user"]["role"], "admin")
        token = cookie.split("checkstead_session=", 1)[1].split(";", 1)[0]
        history = urllib.request.Request(
            self.base + "/api/history",
            headers={"Cookie": f"checkstead_session={token}"},
        )
        with urllib.request.urlopen(history) as response:
            timeline = json.load(response)
        self.assertIn("scans", timeline)
        os.environ["CHECKSTEAD_GITHUB_CLIENT_ID"] = "client-id"
        os.environ["CHECKSTEAD_GITHUB_CLIENT_SECRET"] = "client-secret"
        os.environ["CHECKSTEAD_ENTRA_CLIENT_ID"] = "entra-id"
        os.environ["CHECKSTEAD_ENTRA_CLIENT_SECRET"] = "entra-secret"
        status, body, _headers = self.open("/api/sso")
        payload = json.loads(body)
        self.assertTrue(payload["github"]["enabled"])
        self.assertTrue(payload["entra"]["enabled"])
        self.assertTrue(payload["local"]["enabled"])
        os.environ.pop("CHECKSTEAD_GITHUB_CLIENT_ID", None)
        os.environ.pop("CHECKSTEAD_GITHUB_CLIENT_SECRET", None)
        os.environ.pop("CHECKSTEAD_ENTRA_CLIENT_ID", None)
        os.environ.pop("CHECKSTEAD_ENTRA_CLIENT_SECRET", None)
        self.assertFalse(_local_sign_in("172.17.0.1", "172.17.0.1:8765"))
        self.assertFalse(_local_sign_in("172.17.0.1", "127.0.0.1:8765"))
        os.environ["CHECKSTEAD_LOCAL"] = "1"
        self.assertTrue(_local_sign_in("172.17.0.1", "172.17.0.1:8765"))
        os.environ.pop("CHECKSTEAD_LOCAL", None)

    def test_host_and_forwarded_headers_are_not_a_local_peer(self) -> None:
        self.addCleanup(os.environ.pop, "CHECKSTEAD_LOCAL", None)
        os.environ.pop("CHECKSTEAD_LOCAL", None)
        remote = "172.17.0.1"
        self.assertFalse(_local_sign_in(remote, "127.0.0.1:8765"))
        self.assertFalse(_local_sign_in(remote, "localhost"))
        self.assertFalse(_local_sign_in(remote, "localhost:8765"))
        self.assertFalse(_local_sign_in(remote, "[::1]:8765"))
        self.assertFalse(_local_sign_in("10.0.0.8", "127.0.0.1:8765", "127.0.0.1"))
        self.assertFalse(_local_sign_in("192.168.1.20", "localhost", "127.0.0.1", "for=127.0.0.1", "127.0.0.1"))
        self.assertTrue(_local_sign_in("127.0.0.1", "172.17.0.1:8765", "10.0.0.8", "for=10.0.0.8", "10.0.0.8"))
        self.assertTrue(_local_sign_in("::1", "evil.example"))
        self.assertTrue(_local_sign_in("::ffff:127.0.0.1", "localhost"))
        self.assertTrue(_local_sign_in("127.0.0.2", ""))
        self.assertFalse(_local_sign_in("::ffff:10.0.0.8", "127.0.0.1"))
        self.assertFalse(_local_sign_in("localhost", "localhost"))
        os.environ["CHECKSTEAD_LOCAL"] = "1"
        self.assertTrue(_local_sign_in("172.17.0.1", "not-local"))
        os.environ["CHECKSTEAD_LOCAL"] = "0"
        self.assertFalse(_local_sign_in("127.0.0.1", "127.0.0.1:8765", "127.0.0.1", "for=127.0.0.1", "127.0.0.1"))
        self.assertFalse(_local_sign_in("::1", "localhost"))
        self.assertFalse(_local_sign_in("172.17.0.1", "127.0.0.1:8765"))
        os.environ.pop("CHECKSTEAD_LOCAL", None)

        status, body, _headers = self.open("/api/sso")
        payload = json.loads(body)
        self.assertTrue(payload["local"]["enabled"])
        request = urllib.request.Request(
            self.base + "/api/session/local",
            data=b"{}",
            method="POST",
            headers={
                "Host": "172.17.0.1:8765",
                "X-Forwarded-For": "10.1.2.3",
                "X-Real-IP": "10.1.2.3",
                "Forwarded": "for=10.1.2.3",
            },
        )
        with self.opener.open(request) as response:
            self.assertEqual(response.status, 200)

        os.environ["CHECKSTEAD_LOCAL"] = "0"
        status, body, _headers = self.open("/api/sso")
        self.assertFalse(json.loads(body)["local"]["enabled"])
        denied = urllib.request.Request(
            self.base + "/api/session/local",
            data=b"{}",
            method="POST",
            headers={"Host": "127.0.0.1:8765", "X-Forwarded-For": "127.0.0.1"},
        )
        with self.opener.open(denied) as response:
            self.assertEqual(response.status, 403)
            self.assertIn(b"localhost", response.read())
        os.environ.pop("CHECKSTEAD_LOCAL", None)

    def test_sso_stays_off_until_the_app_is_configured(self) -> None:
        status, body, _headers = self.open("/api/sso")
        payload = json.loads(body)
        self.assertFalse(payload["github"]["enabled"])
        self.assertFalse(payload["entra"]["enabled"])
        self.assertEqual(payload["entra"]["tenant"], "organizations")
        status, body, _headers = self.open("/api/sso/github/start")
        self.assertEqual(status, 404)
        self.assertIn(b"not configured", body)

    def test_github_sign_in_names_the_account_and_drops_the_secret(self) -> None:
        os.environ["CHECKSTEAD_GITHUB_CLIENT_ID"] = "client-id"
        os.environ["CHECKSTEAD_GITHUB_CLIENT_SECRET"] = "client-secret"
        os.environ["CHECKSTEAD_GITHUB_OAUTH"] = self.provider
        os.environ["CHECKSTEAD_GITHUB_API"] = self.provider
        status, _body, headers = self.open("/api/sso/github/start")
        self.assertEqual(status, 302)
        location = headers.get("Location")
        self.assertIn("client_id=client-id", location)
        self.assertNotIn("client-secret", location)
        query = parse_qs(urlsplit(location).query)
        state = query["state"][0]
        status, _body, headers = self.open(
            f"/api/sso/github/callback?code=demo-code&state={state}",
            cookie=f"checkstead_sso={state}",
        )
        self.assertEqual(status, 302)
        self.assertEqual(headers.get("Location"), "/")
        session = headers.get("Set-Cookie")
        self.assertIn("checkstead_session=", session)
        self.assertNotIn("client-secret", session)
        data = ROOT / "build" / "tests" / "sso" / self.id().split(".")[-1] / "accounts.sqlite"
        self.assertNotIn(b"client-secret", data.read_bytes())
        self.assertNotIn(b"from-provider", data.read_bytes())

    def test_entra_sign_in_uses_the_work_account(self) -> None:
        os.environ["CHECKSTEAD_ENTRA_CLIENT_ID"] = "entra-id"
        os.environ["CHECKSTEAD_ENTRA_CLIENT_SECRET"] = "entra-secret"
        os.environ["CHECKSTEAD_ENTRA_AUTHORIZE"] = self.provider + "/authorize"
        os.environ["CHECKSTEAD_ENTRA_TOKEN"] = self.provider + "/token"
        os.environ["CHECKSTEAD_ENTRA_USERINFO"] = self.provider + "/userinfo"
        status, _body, headers = self.open("/api/sso/entra/start")
        self.assertEqual(status, 302)
        self.assertIn("client_id=entra-id", headers.get("Location"))
        self.assertNotIn("entra-secret", headers.get("Location"))
        state = parse_qs(urlsplit(headers.get("Location")).query)["state"][0]
        status, body, headers = self.open(
            f"/api/sso/entra/callback?code=demo-code&state={state}",
            cookie=f"checkstead_sso={state}",
        )
        self.assertEqual(status, 302, body)
        token = headers.get("Set-Cookie").split("checkstead_session=", 1)[1].split(";", 1)[0]
        request = urllib.request.Request(
            self.base + "/api/session",
            headers={"Cookie": f"checkstead_session={token}"},
        )
        with urllib.request.urlopen(request) as response:
            user = json.load(response)["user"]
        self.assertEqual(user["provider"], "entra")
        self.assertEqual(user["login"], "ada@contoso.com")
        self.assertEqual(user["displayName"], "Ada Admin")
        self.assertEqual(user["role"], "admin")
