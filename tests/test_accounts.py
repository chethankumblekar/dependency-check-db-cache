"""GitHub and Azure DevOps tokens identify users. The server does not keep the token."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.accounts import AccountError, AccountStore  # noqa: E402
from checkstead.identity import AuthError, Identity, default_fetch, identify  # noqa: E402


def github_user(url: str, headers: dict[str, str]) -> dict:
    assert url.endswith("/user")
    assert headers["Authorization"] == "Bearer ghp_example"
    return {"login": "octocat", "id": 7, "name": "The Octocat"}


def azure_user(url: str, headers: dict[str, str]) -> dict:
    assert "/example-org/_apis/connectionData" in url
    assert headers["Authorization"].startswith("Basic ")
    return {
        "authenticatedUser": {
            "id": "aad-1",
            "customDisplayName": "Ada Admin",
            "providerDisplayName": "Ada Admin <ada@example.com>",
            "properties": {"Account": {"$value": "ada"}},
        }
    }


class IdentityTests(TestCase):
    def test_github_token_names_the_account(self) -> None:
        identity = identify("github", "ghp_example", fetch=github_user)
        self.assertEqual(identity, Identity("github", "7", "octocat", "The Octocat"))

    def test_azure_devops_token_needs_the_organization(self) -> None:
        with self.assertRaises(AuthError):
            identify("azure-devops", "ado-example", fetch=azure_user)
        identity = identify(
            "azure-devops",
            "ado-example",
            organization="example-org",
            fetch=azure_user,
        )
        self.assertEqual(identity.provider, "azure-devops")
        self.assertEqual(identity.login, "ada")
        self.assertEqual(identity.subject, "aad-1")

    def test_gitlab_is_not_connected(self) -> None:
        with self.assertRaises(AuthError) as caught:
            identify("gitlab", "glpat-example", fetch=github_user)
        self.assertIn("not connected", str(caught.exception))

    def test_live_fetch_reads_the_provider_response(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/user":
                    self.send_response(404)
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != "Bearer live-token":
                    self.send_response(401)
                    self.end_headers()
                    return
                body = json.dumps({"login": "local", "id": 3, "name": "Local"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        payload = default_fetch(
            f"http://{host}:{port}/user",
            {"Authorization": "Bearer live-token"},
        )
        self.assertEqual(payload["login"], "local")


class AccountTests(TestCase):
    def setUp(self) -> None:
        self.store = AccountStore(ROOT / "build" / "tests" / "accounts" / self.id().split(".")[-1])
        if self.store.path.exists():
            self.store.path.unlink()
        self.store = AccountStore(self.store.data_dir)

    def test_first_sign_in_is_the_administrator_and_the_token_is_not_stored(self) -> None:
        secret = "ghp_example"
        token, user = self.store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        self.assertEqual(user["role"], "admin")
        self.assertEqual(self.store.user_for_session(token)["login"], "octocat")
        saved = self.store.path.read_bytes()
        self.assertNotIn(secret.encode(), saved)
        self.assertNotIn(token.encode(), saved)

    def test_a_later_login_must_be_added_by_an_administrator(self) -> None:
        self.store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with self.assertRaises(AccountError) as caught:
            self.store.sign_in(Identity("github", "8", "ada", "Ada"))
        self.assertEqual(caught.exception.status, 403)
        added = self.store.add_user("github", "Ada", "user")
        self.assertEqual(added["role"], "user")
        _token, user = self.store.sign_in(Identity("github", "8", "ada", "Ada Lovelace"))
        self.assertEqual(user["login"], "ada")
        self.assertEqual(user["displayName"], "Ada Lovelace")
        self.assertEqual(user["role"], "user")

    def test_the_last_administrator_stays(self) -> None:
        _token, admin = self.store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with self.assertRaises(AccountError):
            self.store.set_role(admin["id"], "user")
        with self.assertRaises(AccountError):
            self.store.remove_user(admin["id"])
        other = self.store.add_user("azure-devops", "ada", "admin")
        self.store.remove_user(admin["id"])
        self.assertEqual([user["login"] for user in self.store.list_users()], ["ada"])
        self.assertEqual(other["role"], "admin")

    def test_a_different_subject_does_not_take_the_login(self) -> None:
        self.store.add_user("github", "octocat", "admin")
        self.store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with self.assertRaises(AccountError):
            self.store.sign_in(Identity("github", "99", "octocat", "Someone Else"))


class StoreHardeningTests(TestCase):
    def setUp(self) -> None:
        import shutil

        self.data = ROOT / "build" / "tests" / "accounts-hardening" / self.id().split(".")[-1]
        shutil.rmtree(self.data, ignore_errors=True)

    def test_the_store_is_private_to_this_user(self) -> None:
        import os
        import stat

        AccountStore(self.data)
        self.assertEqual(stat.S_IMODE(os.stat(self.data).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.data / "accounts.sqlite").st_mode), 0o600)

    def test_expired_sessions_are_deleted_on_the_next_sign_in(self) -> None:
        import sqlite3

        store = AccountStore(self.data)
        store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with sqlite3.connect(store.path) as conn:
            conn.execute("UPDATE sessions SET created_at = '2000-01-01T00:00:00Z'")
        store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with sqlite3.connect(store.path) as conn:
            created = [row[0] for row in conn.execute("SELECT created_at FROM sessions")]
        self.assertEqual(len(created), 1)
        self.assertNotEqual(created[0], "2000-01-01T00:00:00Z")


class ConnectionLeakTests(TestCase):
    def test_store_calls_close_their_database_connection(self) -> None:
        import gc
        import shutil
        import sqlite3
        import warnings

        data = ROOT / "build" / "tests" / "accounts-leak"
        shutil.rmtree(data, ignore_errors=True)
        store = AccountStore(data)
        token, _user = store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        opened: list[sqlite3.Connection] = []
        real = sqlite3.connect

        def tracking(*args, **kwargs):
            connection = real(*args, **kwargs)
            opened.append(connection)
            return connection

        from unittest import mock

        with mock.patch("checkstead.accounts.sqlite3.connect", side_effect=tracking):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                for _ in range(50):
                    self.assertIsNotNone(store.user_for_session(token))
                store.list_users()
                gc.collect()
        self.assertEqual(len(opened), 51)
        for connection in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
        self.assertFalse([w for w in caught if "unclosed database" in str(w.message)])
