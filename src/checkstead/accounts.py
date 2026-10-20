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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from checkstead.errors import ChecksteadError
from checkstead.identity import PROVIDERS, Identity, normalize_login

SESSION_DAYS = 14


class AccountError(ChecksteadError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _public(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "provider": row["provider"],
        "login": row["login"],
        "displayName": row["display_name"],
        "role": row["role"],
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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def sign_in(self, identity: Identity) -> tuple[str, dict]:
        key = identity.login.casefold()
        with self._lock, self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            row = conn.execute(
                "SELECT * FROM users WHERE provider = ? AND login_key = ?",
                (identity.provider, key),
            ).fetchone()
            if row is None:
                if count:
                    raise AccountError(
                        "An administrator has to add this login before it can sign in.",
                        status=403,
                    )
                cursor = conn.execute(
                    """
                    INSERT INTO users
                      (provider, subject, login, login_key, display_name, role, created_at)
                    VALUES (?, ?, ?, ?, ?, 'admin', ?)
                    """,
                    (
                        identity.provider,
                        identity.subject,
                        identity.login,
                        key,
                        identity.display_name,
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
                user_id = row["id"]
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
            saved = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return token, _public(saved)

    def user_for_session(self, token: str | None) -> dict | None:
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT users.*, sessions.created_at AS session_created
                FROM sessions JOIN users ON users.id = sessions.user_id
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

    def list_users(self) -> list[dict]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
            return [_public(row) for row in rows]

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
            row = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
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
            updated = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
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
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
