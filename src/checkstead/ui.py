"""Scan timeline and the server that guards it.

The same command runs on a laptop and in the container. A session comes
from GitHub or Microsoft sign-in. The timeline itself is unchanged.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from checkstead.accounts import SESSION_DAYS, AccountError, AccountStore
from checkstead.errors import ChecksteadError
from checkstead.github_app import (
    GITHUB_COOKIE,
    ActionsPermissionRequired,
    begin_manifest,
    clear_pending,
    complete_setup,
    exchange_manifest,
    github_status,
    install_url,
    list_workflow_runs,
    localhost_client,
    pending_account,
    render_github_page,
    render_message,
    render_scan_results,
    rerun_workflow,
    scan_installed_repositories,
)
from checkstead.history import history_payload, load_history
from checkstead.identity import AuthError, Identity, identify, list_providers
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


def choose_scans_dir(cwd: Path, packaged: Path, home: Path) -> Path:
    """Prefer ./ui/scans, then the checkout's scans, then the user install.

    The command can be started from any directory. checkstead setup: scans in the user install.
    """
    local = cwd / "ui" / "scans"
    if local.is_dir():
        return local
    if packaged.is_dir():
        return packaged
    return home / "scans"


def default_scans_dir() -> Path:
    from checkstead.scan import home_root

    return choose_scans_dir(
        Path.cwd(),
        Path(__file__).resolve().parents[2] / "ui" / "scans",
        home_root(),
    )


def prepare_scans_dir(path: Path, explicit: bool) -> Path:
    if path.is_dir():
        return path
    if explicit or path.exists():
        raise ChecksteadError(f"Scan directory not found: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


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


def _local_sign_in(
    client_host: str,
    host_header: str = "",
    forwarded_for: str = "",
    forwarded: str = "",
    real_ip: str = "",
) -> bool:
    """Whether this TCP peer may use localhost sign-in.

    ``CHECKSTEAD_LOCAL=1`` trusts every peer that can open the port. Compose
    uses that because the process sees the Docker bridge address, and it is
    safe only when the published port is bound to the host loopback.
    ``CHECKSTEAD_LOCAL=0`` disables localhost sign-in for every peer, including
    a reverse proxy that connects from 127.0.0.1. When the variable is unset,
    only a loopback peer address is accepted.

    ``host_header``, ``forwarded_for``, ``forwarded``, and ``real_ip`` are the
    Host, X-Forwarded-For, Forwarded, and X-Real-IP values. They are not read.
    A client can set all of them.
    """
    del host_header, forwarded_for, forwarded, real_ip
    mode = os.environ.get("CHECKSTEAD_LOCAL", "").strip()
    if mode == "1":
        return True
    if mode == "0":
        return False
    return localhost_client(client_host)


def _request_is_local(handler: BaseHTTPRequestHandler) -> bool:
    headers = handler.headers
    return _local_sign_in(
        handler.client_address[0],
        headers.get("Host", ""),
        headers.get("X-Forwarded-For", ""),
        headers.get("Forwarded", ""),
        headers.get("X-Real-IP", ""),
    )


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
            if path == "/api/health":
                self._json(200, {"ok": True})
                return
            if path in {"/", "/index.html"}:
                self._send(200, "text/html; charset=utf-8", PAGE.read_bytes())
                return
            if path == "/api/providers":
                self._json(200, list_providers())
                return
            if path == "/api/sso":
                status = sso_status()
                status["local"] = {"enabled": _request_is_local(self)}
                self._json(200, status)
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
            if path == "/api/github/runs":
                if not self._github_ok():
                    return
                self._github_runs()
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
            if path == "/api/session/local":
                self._local_session()
                return
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
            if path == "/api/github/rerun":
                if not self._github_ok():
                    return
                self._github_rerun()
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
                location = authorize_url(kind, public_base(host, self.client_address[0]), state)
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
                identity = exchange(
                    kind,
                    code,
                    public_base(self.headers.get("Host", ""), self.client_address[0]),
                )
                token, _user = store.sign_in(identity)
            except (AuthError, AccountError) as exc:
                self._page(getattr(exc, "status", 401), str(exc))
                return
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", _session_cookie(token, SESSION_DAYS * 24 * 3600))
            self.send_header("Set-Cookie", f"{STATE_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
            self.end_headers()

        def _local_session(self) -> None:
            if not _request_is_local(self):
                self._json(403, {"error": "This sign-in is only available on localhost."})
                return
            try:
                token, user = store.sign_in(Identity("local", "local", "local", "This computer"))
            except AccountError as exc:
                self._json(exc.status, {"error": str(exc)})
                return
            self._json(200, {"user": user}, _session_cookie(token, SESSION_DAYS * 24 * 3600))

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
                chosen = {
                    "user": "User",
                    "organization": "Organization",
                }.get(str(fields.get("account") or "").strip().lower())
                page = begin_manifest(
                    store.data_dir,
                    str(fields.get("login") or fields.get("organization") or ""),
                    public_base(self.headers.get("Host", ""), self.client_address[0]),
                    state,
                    github_transport,
                    chosen,
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
                organization, account_type = pending_account(store.data_dir, state)
                exchange_manifest(
                    store.data_dir,
                    code,
                    organization,
                    github_transport,
                    account_type,
                )
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
            self._redirect(link)

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
                    "Scan this account's repositories",
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
                    self._html(400, render_message("Scan", [str(exc)]))
                return
            except Exception:
                if self._wants_json():
                    self._json(400, {"error": "The scan could not finish."})
                else:
                    self._html(400, render_message("Scan", ["The scan could not finish."]))
                return
            if self._wants_json():
                self._json(200, {"scans": scans})
                return
            self._html(200, render_scan_results(scans))

        def _github_runs(self) -> None:
            try:
                payload = list_workflow_runs(store.data_dir, github_transport)
            except ActionsPermissionRequired as exc:
                self._json(
                    200,
                    {
                        "connected": True,
                        "runs": [],
                        "approvalUrl": exc.approval_url,
                        "notice": str(exc),
                    },
                )
                return
            except ChecksteadError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(200, payload)

        def _github_rerun(self) -> None:
            body = self._body()
            if body is None:
                return
            try:
                result = rerun_workflow(
                    store.data_dir,
                    str(body.get("repository") or ""),
                    body.get("run"),
                    github_transport,
                )
            except ActionsPermissionRequired as exc:
                self._json(403, {"error": str(exc), "approvalUrl": exc.approval_url})
                return
            except ChecksteadError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(202, result)

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

        def _common_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("Cache-Control", "no-store")

        def _redirect(self, location: str) -> None:
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self._common_headers()
            self.end_headers()

        def _html(self, status: int, page: str, cookie: str | None = None) -> None:
            body = page.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._common_headers()
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
            self._common_headers()
            if cookie:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(body)

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self._common_headers()
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def warn_exposed_local_sign_in(host: str) -> None:
    """CHECKSTEAD_LOCAL=1 trusts every client that can open the port."""
    if os.environ.get("CHECKSTEAD_LOCAL") != "1":
        return
    name = host.strip().lower().strip("[]")
    if name in {"127.0.0.1", "::1", "localhost"}:
        return
    print(
        "checkstead: CHECKSTEAD_LOCAL=1 lets any client that can reach this port "
        "become the first administrator. Publish 127.0.0.1:8765:8765, or set "
        "CHECKSTEAD_LOCAL=0.",
        file=sys.stderr,
    )


def serve(
    scans_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
    data_dir: Path | None = None,
) -> None:
    warn_exposed_local_sign_in(host)
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
