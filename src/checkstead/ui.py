"""Scan timeline and the server that guards it.

The same command runs on a laptop and in the container. A session comes
from a GitHub or Azure DevOps token. The timeline itself is unchanged.
"""

from __future__ import annotations

import json
import os
import secrets
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from checkstead.accounts import SESSION_DAYS, AccountError, AccountStore
from checkstead.errors import ChecksteadError
from checkstead.github_app import (
    GITHUB_COOKIE,
    begin_manifest,
    clear_pending,
    complete_setup,
    exchange_manifest,
    github_status,
    install_url,
    localhost_client,
    pending_organization,
    render_github_page,
    render_message,
    render_scan_results,
    scan_installed_repositories,
)
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


def _github_cookie(state: str) -> str:
    parts = [
        f"{GITHUB_COOKIE}={state}",
        "HttpOnly",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=600",
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
    github_transport=None,
    github_scan=None,
    github_fetch_zip=None,
    config_cwd: Path | None = None,
) -> ThreadingHTTPServer:
    scans_dir = scans_dir.resolve()
    store = AccountStore(data_dir or default_data_dir())
    project_cwd = config_cwd or Path.cwd()

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
            if path == "/github":
                if not self._github_ok():
                    return
                page = render_github_page(github_status(store.data_dir))
                self._send(200, "text/html; charset=utf-8", page.encode("utf-8"))
                return
            if path == "/api/github":
                if not self._github_ok():
                    return
                self._json(200, github_status(store.data_dir))
                return
            if path == "/api/github/manifest/callback":
                if not self._github_ok():
                    return
                self._github_callback(query)
                return
            if path == "/api/github/setup":
                if not self._github_ok():
                    return
                self._github_setup(query)
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
            if path == "/api/github/hook":
                self._github_hook()
                return
            if path == "/api/github/manifest":
                if not self._github_ok():
                    return
                self._github_manifest()
                return
            if path == "/api/github/scan":
                if not self._github_ok():
                    return
                self._github_scan()
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

        def _github_ok(self) -> bool:
            if localhost_client(self.client_address[0]):
                return True
            return self._admin() is not None

        def _github_hook(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            remaining = min(max(length, 0), 1024 * 1024)
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
            self._json(200, {"ok": True})

        def _github_manifest(self) -> None:
            fields = self._fields()
            if fields is None:
                return
            state = secrets.token_urlsafe(24)
            try:
                page = begin_manifest(
                    store.data_dir,
                    str(fields.get("organization") or ""),
                    public_base(self.headers.get("Host", "")),
                    state,
                )
            except (AuthError, ChecksteadError) as exc:
                self._html(400, render_message("GitHub", [str(exc)]))
                return
            self._html(200, page, _github_cookie(state))

        def _github_callback(self, query: dict[str, list[str]]) -> None:
            if (query.get("error") or [""])[0]:
                clear_pending(store.data_dir)
                self._html(400, render_message("GitHub", ["GitHub did not create the app."]))
                return
            code = (query.get("code") or [""])[0]
            state = (query.get("state") or [""])[0]
            saved = _cookie_named(self.headers.get("Cookie"), GITHUB_COOKIE)
            if not state or state != saved:
                self._html(400, render_message("GitHub", ["GitHub could not be confirmed. Create the app again."]))
                return
            try:
                organization = pending_organization(store.data_dir, state)
                created = exchange_manifest(store.data_dir, code, organization, github_transport)
                link = install_url(store.data_dir)
            except ChecksteadError as exc:
                clear_pending(store.data_dir)
                self._html(400, render_message("GitHub", [str(exc)]))
                return
            except Exception:
                clear_pending(store.data_dir)
                self._html(400, render_message("GitHub", ["GitHub did not create the app."]))
                return
            clear_pending(store.data_dir)
            org = str(created.get("organization") or organization)
            self._html(
                200,
                render_message(
                    "GitHub App created",
                    [f"The GitHub App {created.get('slug')} is ready for {org}."],
                    link,
                    f"Install it on {org}",
                ),
            )

        def _github_setup(self, query: dict[str, list[str]]) -> None:
            installation_id = (query.get("installation_id") or [""])[0]
            try:
                accepted = complete_setup(store.data_dir, installation_id, github_transport)
            except ChecksteadError as exc:
                self._html(400, render_message("GitHub", [str(exc)]))
                return
            except Exception:
                self._html(400, render_message("GitHub", ["GitHub did not accept the installation."]))
                return
            org = str(accepted.get("organization") or "")
            self._html(
                200,
                render_message(
                    "GitHub App installed",
                    [f"Checkstead accepted the installation on {org}."],
                    "/github",
                    "Scan the organization's repositories",
                ),
            )

        def _github_scan(self) -> None:
            try:
                scans = scan_installed_repositories(
                    store.data_dir,
                    scans_dir,
                    project_cwd,
                    github_transport,
                    github_scan,
                    github_fetch_zip,
                )
            except ChecksteadError as exc:
                if self._wants_json():
                    self._json(400, {"error": str(exc)})
                else:
                    self._html(400, render_message("Organization scan", [str(exc)]))
                return
            except Exception:
                if self._wants_json():
                    self._json(400, {"error": "The organization scan could not finish."})
                else:
                    self._html(400, render_message("Organization scan", ["The organization scan could not finish."]))
                return
            if self._wants_json():
                self._json(200, {"scans": scans})
                return
            self._html(200, render_scan_results(scans))

        def _wants_json(self) -> bool:
            return "application/json" in self.headers.get("Accept", "")

        def _fields(self) -> dict | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._json(400, {"error": "Request body is not valid."})
                return None
            if length < 0 or length > MAX_BODY:
                self._json(413, {"error": "Request is too large."})
                return None
            raw = self.rfile.read(length) if length else b""
            content_type = self.headers.get("Content-Type", "")
            if "application/json" in content_type or raw[:1] == b"{":
                try:
                    body = json.loads(raw.decode("utf-8")) if raw else {}
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._json(400, {"error": "Request body is not valid."})
                    return None
                if not isinstance(body, dict):
                    self._json(400, {"error": "Request body is not valid."})
                    return None
                return body
            try:
                parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
            except UnicodeDecodeError:
                self._json(400, {"error": "Request body is not valid."})
                return None
            return {key: values[0] if values else "" for key, values in parsed.items()}

        def _html(self, status: int, page: str, cookie: str | None = None) -> None:
            body = page.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

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
    print(f"github         http://{shown_host}:{shown_port}/github")
    print(f"scans          {scans_dir.resolve()}")
    print(f"accounts       {(data_dir or default_data_dir()).resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
