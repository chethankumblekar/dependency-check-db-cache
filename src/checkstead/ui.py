"""Scan timeline and the server that guards it.

The same command runs on a laptop and in the container. A session comes
from a GitHub or Azure DevOps token. The timeline itself is unchanged.
"""

from __future__ import annotations

import json
import os
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from checkstead.accounts import SESSION_DAYS, AccountError, AccountStore
from checkstead.history import history_payload, load_history
from checkstead.identity import AuthError, identify, list_providers
from checkstead.sso import (
    STATE_COOKIE,
    authorize_url,
    exchange,
    new_state,
    public_base,
    sso_status,
    state_cookie,
)

PAGE = Path(__file__).resolve().with_name("ui_page.html")
COOKIE = "checkstead_session"
MAX_BODY = 8192


def default_scans_dir() -> Path:
    local = Path.cwd() / "ui" / "scans"
    if local.is_dir():
        return local
    return Path(__file__).resolve().parents[2] / "ui" / "scans"


def default_data_dir() -> Path:
    override = os.environ.get("CHECKSTEAD_DATA")
    if override:
        return Path(override)
    return Path.home() / ".local" / "share" / "checkstead"


def _cookie_named(header: str | None, name: str) -> str | None:
    if not header:
        return None
    for part in header.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key == name and value:
            return value
    return None


def _cookie(header: str | None) -> str | None:
    return _cookie_named(header, COOKIE)


def _session_cookie(token: str, max_age: int) -> str:
    parts = [
        f"{COOKIE}={token}",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        f"Max-Age={max_age}",
    ]
    if os.environ.get("CHECKSTEAD_COOKIE_SECURE") == "1":
        parts.append("Secure")
    return "; ".join(parts)


def bind_server(
    scans_dir: Path,
    host: str = "127.0.0.1",
    port: int = 0,
    data_dir: Path | None = None,
    fetch=None,
) -> ThreadingHTTPServer:
    scans_dir = scans_dir.resolve()
    store = AccountStore(data_dir or default_data_dir())

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path in {"/", "/index.html"}:
                self._send(200, "text/html; charset=utf-8", PAGE.read_bytes())
                return
            if path == "/api/providers":
                self._json(200, list_providers())
                return
            if path == "/api/sso":
                self._json(200, sso_status())
                return
            if path in {"/api/sso/github/start", "/api/sso/entra/start"}:
                self._sso_start(path.split("/")[3])
                return
            if path in {"/api/sso/github/callback", "/api/sso/entra/callback"}:
                self._sso_callback(path.split("/")[3], query)
                return
            if path == "/api/session":
                user = store.user_for_session(_cookie(self.headers.get("Cookie")))
                if user is None:
                    self._json(401, {"error": "Sign in required."})
                    return
                self._json(200, {"user": user})
                return
            if path == "/api/history":
                if self._user() is None:
                    return
                self._json(200, history_payload(load_history(scans_dir)))
                return
            if path == "/api/admin/users":
                if self._admin() is None:
                    return
                self._json(200, {"users": store.list_users()})
                return
            self._send(404, "text/plain; charset=utf-8", b"Not found\n")

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/session":
                body = self._body()
                if body is None:
                    return
                try:
                    identity = identify(
                        str(body.get("provider") or ""),
                        str(body.get("token") or ""),
                        body.get("organization"),
                        fetch,
                    )
                    token, user = store.sign_in(identity)
                except (AuthError, AccountError) as exc:
                    status = getattr(exc, "status", 401)
                    self._json(status, {"error": str(exc)})
                    return
                self._json(200, {"user": user}, _session_cookie(token, SESSION_DAYS * 24 * 3600))
                return
            if path == "/api/admin/users":
                if self._admin() is None:
                    return
                body = self._body()
                if body is None:
                    return
                try:
                    user = store.add_user(
                        str(body.get("provider") or ""),
                        str(body.get("login") or ""),
                        str(body.get("role") or "user"),
                    )
                except (AuthError, AccountError) as exc:
                    self._json(getattr(exc, "status", 400), {"error": str(exc)})
                    return
                self._json(201, {"user": user})
                return
            self._send(404, "text/plain; charset=utf-8", b"Not found\n")

        def do_PATCH(self) -> None:
            user_id = self._user_id()
            if user_id is None:
                return
            if self._admin() is None:
                return
            body = self._body()
            if body is None:
                return
            try:
                user = store.set_role(user_id, str(body.get("role") or ""))
            except AccountError as exc:
                self._json(exc.status, {"error": str(exc)})
                return
            self._json(200, {"user": user})

        def do_DELETE(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/api/session":
                store.sign_out(_cookie(self.headers.get("Cookie")))
                self._json(200, {"signedOut": True}, _session_cookie("gone", 0))
                return
            user_id = self._user_id()
            if user_id is None:
                return
            if self._admin() is None:
                return
            try:
                store.remove_user(user_id)
            except AccountError as exc:
                self._json(exc.status, {"error": str(exc)})
                return
            self._json(200, {"removed": user_id})

        def _sso_start(self, kind: str) -> None:
            host = self.headers.get("Host", "")
            try:
                state = new_state()
                location = authorize_url(kind, public_base(host), state)
            except AuthError as exc:
                self._page(404, str(exc))
                return
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Set-Cookie", state_cookie(state))
            self.end_headers()

        def _sso_callback(self, kind: str, query: dict[str, list[str]]) -> None:
            code = (query.get("code") or [""])[0]
            state = (query.get("state") or [""])[0]
            saved = _cookie_named(self.headers.get("Cookie"), STATE_COOKIE)
            if not code or not state or state != saved:
                self._page(400, "Sign-in could not be confirmed. Start again.")
                return
            try:
                identity = exchange(kind, code, public_base(self.headers.get("Host", "")))
                token, _user = store.sign_in(identity)
            except (AuthError, AccountError) as exc:
                self._page(getattr(exc, "status", 401), str(exc))
                return
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", _session_cookie(token, SESSION_DAYS * 24 * 3600))
            self.send_header("Set-Cookie", f"{STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            self.end_headers()

        def _page(self, status: int, message: str) -> None:
            body = (
                "<!DOCTYPE html><html lang=\"en\"><meta charset=\"utf-8\">"
                f"<title>Checkstead</title><p>{escape(message)}</p>"
                "<p><a href=\"/\">Back to sign in</a></p></html>"
            ).encode("utf-8")
            self._send(status, "text/html; charset=utf-8", body)

        def _user_id(self) -> int | None:
            path = unquote(self.path.split("?", 1)[0])
            prefix = "/api/admin/users/"
            if not path.startswith(prefix) or not path[len(prefix) :].isdigit():
                self._send(404, "text/plain; charset=utf-8", b"Not found\n")
                return None
            return int(path[len(prefix) :])

        def _user(self) -> dict | None:
            user = store.user_for_session(_cookie(self.headers.get("Cookie")))
            if user is None:
                self._json(401, {"error": "Sign in required."})
                return None
            return user

        def _admin(self) -> dict | None:
            user = self._user()
            if user is None:
                return None
            if user["role"] != "admin":
                self._json(403, {"error": "An administrator has to do that."})
                return None
            return user

        def _body(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "Request body is not valid."})
                return None
            if length < 0 or length > MAX_BODY:
                self._json(413, {"error": "Request is too large."})
                return None
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, {"error": "Request body is not valid."})
                return None
            if not isinstance(body, dict):
                self._json(400, {"error": "Request body is not valid."})
                return None
            organization = body.get("organization")
            if organization is not None:
                body["organization"] = str(organization)
            return body

        def _json(self, status: int, payload: dict, cookie: str | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def serve(
    scans_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    data_dir: Path | None = None,
) -> None:
    server = bind_server(scans_dir, host, port, data_dir)
    shown_host, shown_port = server.server_address[:2]
    print(f"checkstead ui  http://{shown_host}:{shown_port}/")
    print(f"scans          {scans_dir.resolve()}")
    print(f"accounts       {(data_dir or default_data_dir()).resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
