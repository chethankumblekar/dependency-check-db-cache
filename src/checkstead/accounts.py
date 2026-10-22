"""Users and administrators for one Checkstead server.

A GitHub or Azure DevOps token is checked and then discarded. The server
keeps the account and its own session, the way a SonarQube server keeps
users after the identity provider has authenticated them.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from checkstead.avatars import Avatar
from checkstead.errors import ChecksteadError
from checkstead.identity import PROVIDERS, Identity, normalize_login

SESSION_DAYS = 14
# Every user read carries the picture's version, never its bytes.
_USERS = (
    "SELECT users.*, avatars.etag AS avatar_etag "
    "FROM users LEFT JOIN avatars ON avatars.user_id = users.id"
)


class AccountError(ChecksteadError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public(row: sqlite3.Row) -> dict:
    etag = row["avatar_etag"]
    return {
        "id": row["id"],
        "provider": row["provider"],
        "login": row["login"],
        "displayName": row["display_name"],
        "role": row["role"],
        # Versioned, so a new picture is a new URL and the old one can be cached.
        "avatar": f"/api/users/{row['id']}/avatar?v={etag}" if etag else None,
    }


class AccountStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            # Sessions and the GitHub App key live here. Only this user reads them.
            os.chmod(self.data_dir, 0o700)
        except OSError:
            pass
        self.path = self.data_dir / "accounts.sqlite"
        if not self.path.exists():
            # Create the file 0600 before SQLite opens it, so it is never
            # readable by others, not even for the first write.
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT, 0o600))
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                  id INTEGER PRIMARY KEY,
                  provider TEXT NOT NULL,
                  subject TEXT,
                  login TEXT NOT NULL,
                  login_key TEXT NOT NULL,
                  display_name TEXT NOT NULL,
                  role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                  created_at TEXT NOT NULL,
                  UNIQUE (provider, login_key)
                );
                CREATE TABLE IF NOT EXISTS avatars (
                  user_id INTEGER PRIMARY KEY,
                  mime TEXT NOT NULL,
                  data BLOB NOT NULL,
                  etag TEXT NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                  token_hash TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  created_at TEXT NOT NULL,
                  FOREIGN KEY (user_id) REFERENCES users(id)
                );
                """
            )
        if self.path.exists():
            os.chmod(self.path, 0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One transaction on a connection that is closed afterwards.

        ``with sqlite3.connect(...)`` commits but does not close. Every
        session check opened one, and under load the server held thousands
        of open file handles until garbage collection caught up.
        """
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def sign_in(self, identity: Identity, group_role: str | None = None) -> tuple[str, dict]:
        """Start a session for a known login.

        ``group_role`` is what an Entra security group grants ("admin" or
        "user"). It admits a login nobody added and promotes a member to
        administrator. It never demotes: a group change must not lock out
        the last administrator.
        """
        if group_role not in {None, "admin", "user"}:
            raise AccountError("Role must be admin or user.")
        key = identity.login.casefold()
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            row = conn.execute(
                "SELECT * FROM users WHERE provider = ? AND login_key = ?",
                (identity.provider, key),
            ).fetchone()
            if row is None:
                if count and group_role is None:
                    raise AccountError(
                        "An administrator has to add this login before it can sign in.",
                        status=403,
                    )
                role = "admin" if not count else group_role
                cursor = conn.execute(
                    """
                    INSERT INTO users
                      (provider, subject, login, login_key, display_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identity.provider,
                        identity.subject,
                        identity.login,
                        key,
                        identity.display_name,
                        role,
                        _now(),
                    ),
                )
                user_id = cursor.lastrowid
            else:
                if row["subject"] and row["subject"] != identity.subject:
                    raise AccountError(
                        "This token does not match the account on file.",
                        status=403,
                    )
                conn.execute(
                    "UPDATE users SET subject = ?, login = ?, display_name = ? WHERE id = ?",
                    (identity.subject, identity.login, identity.display_name, row["id"]),
                )
                if group_role == "admin" and row["role"] != "admin":
                    conn.execute("UPDATE users SET role = 'admin' WHERE id = ?", (row["id"],))
                user_id = row["id"]
            if identity.avatar is not None:
                # No picture this time keeps the last one: a provider outage
                # should not blank everyone's face.
                conn.execute(
                    "INSERT OR REPLACE INTO avatars (user_id, mime, data, etag) VALUES (?, ?, ?, ?)",
                    (user_id, identity.avatar.mime, identity.avatar.data, identity.avatar.etag),
                )
            cutoff = (datetime.now(timezone.utc) - timedelta(days=SESSION_DAYS)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            conn.execute("DELETE FROM sessions WHERE created_at < ?", (cutoff,))
            token = secrets.token_urlsafe(32)
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, created_at) VALUES (?, ?, ?)",
                (hashlib.sha256(token.encode("utf-8")).hexdigest(), user_id, _now()),
            )
            conn.commit()
            saved = conn.execute(f"{_USERS} WHERE users.id = ?", (user_id,)).fetchone()
            return token, _public(saved)

    def user_for_session(self, token: str | None) -> dict | None:
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT users.*, sessions.created_at AS session_created,
                       avatars.etag AS avatar_etag
                FROM sessions JOIN users ON users.id = sessions.user_id
                LEFT JOIN avatars ON avatars.user_id = users.id
                WHERE sessions.token_hash = ?
                """,
                (digest,),
            ).fetchone()
            if row is None:
                return None
            created = datetime.strptime(row["session_created"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            if datetime.now(timezone.utc) - created > timedelta(days=SESSION_DAYS):
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
                conn.commit()
                return None
            return _public(row)

    def sign_out(self, token: str | None) -> None:
        if not token:
            return
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
            conn.commit()

    def avatar(self, user_id: int) -> Avatar | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT mime, data FROM avatars WHERE user_id = ?", (user_id,)
            ).fetchone()
            return Avatar(row["mime"], bytes(row["data"])) if row else None

    def list_users(self) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(f"{_USERS} ORDER BY users.id").fetchall()
            return [_public(row) for row in rows]

    def has_provider(self, provider: str) -> bool:
        """Whether any login on file uses this provider. Says nothing about who."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT 1 FROM users WHERE provider = ? LIMIT 1", (provider,)).fetchone()
            return row is not None

    def add_user(self, provider: str, login: str, role: str) -> dict:
        if provider not in PROVIDERS:
            raise AccountError("That Git host is not connected yet.")
        if role not in {"admin", "user"}:
            raise AccountError("Role must be admin or user.")
        cleaned = normalize_login(login)
        key = cleaned.casefold()
        with self._lock, self._connect() as conn:
            try:
                cursor = conn.execute(
                    """
                    INSERT INTO users
                      (provider, subject, login, login_key, display_name, role, created_at)
                    VALUES (?, NULL, ?, ?, ?, ?, ?)
                    """,
                    (provider, cleaned, key, cleaned, role, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise AccountError("That login is already on this server.") from exc
            conn.commit()
            row = conn.execute(f"{_USERS} WHERE users.id = ?", (cursor.lastrowid,)).fetchone()
            return _public(row)

    def set_role(self, user_id: int, role: str) -> dict:
        if role not in {"admin", "user"}:
            raise AccountError("Role must be admin or user.")
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise AccountError("No such user.", status=404)
            if row["role"] == "admin" and role != "admin":
                admins = conn.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin'"
                ).fetchone()[0]
                if admins <= 1:
                    raise AccountError(
                        "The last administrator cannot be changed.",
                        status=409,
                    )
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
            conn.commit()
            updated = conn.execute(f"{_USERS} WHERE users.id = ?", (user_id,)).fetchone()
            return _public(updated)

    def remove_user(self, user_id: int) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row is None:
                raise AccountError("No such user.", status=404)
            if row["role"] == "admin":
                admins = conn.execute(
                    "SELECT COUNT(*) FROM users WHERE role = 'admin'"
                ).fetchone()[0]
                if admins <= 1:
                    raise AccountError(
                        "The last administrator cannot be removed.",
                        status=409,
                    )
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM avatars WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
