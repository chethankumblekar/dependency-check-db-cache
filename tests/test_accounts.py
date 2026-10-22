"""GitHub and Azure DevOps tokens identify users. The server does not keep the token."""

from __future__ import annotations

import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead import avatars  # noqa: E402
from checkstead.accounts import AccountError, AccountStore  # noqa: E402
from checkstead.identity import AuthError, Identity, default_fetch, identify  # noqa: E402


def github_user(url: str, headers: dict[str, str]) -> dict:
    assert url.endswith("/user")
    assert headers["Authorization"] == "Bearer ghp_example"
    return {"login": "octocat", "id": 7, "name": "The Octocat"}


def azure_user(url: str, headers: dict[str, str]) -> dict:
    assert url.endswith("/example-org/_apis/connectionData?api-version=7.1-preview.1")
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
        from contextlib import closing

        store = AccountStore(self.data)
        store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        # `with sqlite3.connect()` commits but does not close; a leftover
        # connection later trips ConnectionLeakTests when GC collects it.
        with closing(sqlite3.connect(store.path)) as conn, conn:
            conn.execute("UPDATE sessions SET created_at = '2000-01-01T00:00:00Z'")
        store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        with closing(sqlite3.connect(store.path)) as conn:
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


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class AvatarTests(TestCase):
    def test_only_raster_images_within_the_size_limit_are_kept(self) -> None:
        self.assertEqual(avatars.from_bytes(PNG).mime, "image/png")
        self.assertEqual(avatars.from_bytes(b"\xff\xd8\xff\xe0rest").mime, "image/jpeg")
        self.assertEqual(avatars.from_bytes(b"GIF89arest").mime, "image/gif")
        self.assertEqual(avatars.from_bytes(b"RIFF\x00\x00\x00\x00WEBPVP8 ").mime, "image/webp")
        self.assertIsNone(avatars.from_bytes(b"<svg><script>alert(1)</script></svg>"))
        self.assertIsNone(avatars.from_bytes(b"<html>"))
        self.assertIsNone(avatars.from_bytes(b""))
        self.assertIsNone(avatars.from_bytes(PNG + b"\x00" * avatars.MAX_BYTES))

    def test_github_avatar_is_asked_for_at_the_shown_size(self) -> None:
        self.assertEqual(
            avatars.sized("https://avatars.githubusercontent.com/u/7?v=4&s=460"),
            "https://avatars.githubusercontent.com/u/7?v=4&s=96",
        )

    def test_azure_generated_initials_are_not_kept(self) -> None:
        encoded = base64.b64encode(PNG).decode()
        self.assertIsNone(avatars.from_azure_payload({"isAutoGenerated": True, "value": encoded}))
        self.assertEqual(avatars.from_azure_payload({"isAutoGenerated": False, "value": encoded}).data, PNG)
        self.assertIsNone(avatars.from_azure_payload({"value": "not base64!"}))
        self.assertIsNone(avatars.from_azure_payload(["not", "a", "dict"]))

    def test_azure_devops_picture_comes_from_the_profile_service(self) -> None:
        seen = []

        def fetch(url: str, headers: dict[str, str]) -> dict:
            seen.append(url)
            if "/avatar" in url:
                self.assertTrue(url.startswith("https://vssps.dev.azure.com/example-org/_apis/profile/profiles/me/avatar"))
                self.assertTrue(headers["Authorization"].startswith("Basic "))
                return {"isAutoGenerated": False, "value": base64.b64encode(PNG).decode()}
            return azure_user(url, headers)

        identity = identify("azure-devops", "ado-example", organization="example-org", fetch=fetch)
        self.assertEqual(identity.avatar.data, PNG)
        self.assertEqual(len(seen), 2)

    def test_a_picture_that_cannot_be_read_does_not_stop_sign_in(self) -> None:
        def fetch(url: str, headers: dict[str, str]) -> dict:
            if "/avatar" in url:
                raise AuthError("The identity provider rejected this token.")
            return azure_user(url, headers)

        identity = identify("azure-devops", "ado-example", organization="example-org", fetch=fetch)
        self.assertEqual(identity.login, "ada")
        self.assertIsNone(identity.avatar)


class AvatarStoreTests(TestCase):
    def setUp(self) -> None:
        self.store = AccountStore(ROOT / "build" / "tests" / "accounts" / self.id().split(".")[-1])
        if self.store.path.exists():
            self.store.path.unlink()
        self.store = AccountStore(self.store.data_dir)

    def test_picture_is_stored_versioned_kept_and_removed_with_the_user(self) -> None:
        first = avatars.from_bytes(PNG)
        token, user = self.store.sign_in(Identity("github", "7", "octocat", "The Octocat", first))
        self.assertEqual(user["avatar"], f"/api/users/{user['id']}/avatar?v={first.etag}")
        self.assertEqual(self.store.user_for_session(token)["avatar"], user["avatar"])
        self.assertEqual(self.store.avatar(user["id"]), first)
        # A sign-in where the provider gave no picture keeps the last one.
        _token, again = self.store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        self.assertEqual(again["avatar"], user["avatar"])
        # A new picture is a new URL.
        second = avatars.from_bytes(b"GIF89a" + b"\x01" * 16)
        _token, changed = self.store.sign_in(Identity("github", "7", "octocat", "The Octocat", second))
        self.assertNotEqual(changed["avatar"], user["avatar"])
        added = self.store.add_user("github", "ada", "user")
        self.assertIsNone(added["avatar"])
        self.store.sign_in(Identity("github", "8", "ada", "Ada", first))
        listed = {item["login"]: item for item in self.store.list_users()}
        self.assertIsNotNone(listed["ada"]["avatar"])
        self.store.remove_user(added["id"])
        self.assertIsNone(self.store.avatar(added["id"]))

    def test_an_existing_database_gains_the_picture_table(self) -> None:
        import sqlite3
        from contextlib import closing

        with closing(sqlite3.connect(self.store.path)) as conn, conn:
            conn.execute("DROP TABLE avatars")
        store = AccountStore(self.store.data_dir)
        _token, user = store.sign_in(Identity("github", "7", "octocat", "The Octocat"))
        self.assertIsNone(user["avatar"])
