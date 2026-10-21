"""Scan timeline and the server that guards it.

The same command runs on a laptop and in the container. A session comes
from GitHub or Microsoft sign-in. The timeline itself is unchanged.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import secrets
import sys
import threading
import time
from dataclasses import dataclass
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
    warn_entra_tenant,
)

PAGE = Path(__file__).resolve().with_name("ui_page.html")
_AVATAR_PATH = re.compile(r"/api/users/([0-9]{1,12})/avatar")
COOKIE = "checkstead_session"
MAX_BODY = 8192
# A client that stops sending or reading for this long is dropped. It bounds
# a slow request, not the work a request starts.
SOCKET_TIMEOUT_SECONDS = 30
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})
# Requests that browsers send cross-site without credentials and that change
# nothing. A webhook delivery comes from GitHub, not from a browser.
_UNGUARDED_PATHS = frozenset({"/api/health", "/api/github/hook"})


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


def _host_name(value: str) -> str | None:
    """Lowercased host name from a Host header or an origin netloc, without the port."""
    text = value.strip()
    if not text or any(char in text for char in "\r\n\x00 /\\@?#"):
        return None
    try:
        parsed = urlsplit(f"//{text}")
        name = parsed.hostname
        _ = parsed.port  # raises ValueError on a bad port
    except ValueError:
        return None
    if not name:
        return None
    return name.rstrip(".").lower()


def allowed_hosts() -> frozenset[str]:
    """Host names this server answers to.

    Loopback names always. The host of ``CHECKSTEAD_PUBLIC_BASE`` and every
    name in ``CHECKSTEAD_ALLOWED_HOSTS`` (comma separated) when set. Any other
    Host header is refused, which is what stops a DNS-rebinding page from
    reading this server through a name it controls.
    """
    names = set(LOOPBACK_NAMES)
    base = os.environ.get("CHECKSTEAD_PUBLIC_BASE", "").strip()
    if base:
        parsed = urlsplit(base)
        if parsed.hostname:
            names.add(parsed.hostname.rstrip(".").lower())
    for item in os.environ.get("CHECKSTEAD_ALLOWED_HOSTS", "").split(","):
        name = _host_name(item)
        if name:
            names.add(name)
    return frozenset(names)


def host_allowed(host_header: str) -> bool:
    name = _host_name(host_header)
    return name is not None and name in allowed_hosts()


def origin_allowed(origin: str, host_header: str, fetch_site: str = "") -> bool:
    """Whether a state-changing request came from this server's own pages.

    Browsers send ``Origin`` on every POST, PATCH, and DELETE. It has to name
    the same host and port as ``Host``. ``Origin: null`` is refused. A request
    with neither ``Origin`` nor ``Sec-Fetch-Site`` is not from a browser, so it
    cannot ride a signed-in user's cookie, and it is allowed.
    """
    origin = origin.strip()
    site = fetch_site.strip().lower()
    if origin:
        if origin == "null":
            return False
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            return False
        if parsed.netloc.lower() == host_header.strip().lower():
            return True
        # A reverse proxy may rewrite Host. The configured public origin is
        # still this server's own pages.
        base = os.environ.get("CHECKSTEAD_PUBLIC_BASE", "").strip().rstrip("/")
        return bool(base) and f"{parsed.scheme}://{parsed.netloc}".lower() == base.lower()
    if site:
        return site in {"same-origin", "none"}
    return True


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


@dataclass(frozen=True)
class HistoryBody:
    raw: bytes
    gzipped: bytes


class HistoryCache:
    """The /api/history response, rebuilt only when a scan report changes.

    Building it parses every scan; with a few hundred scans that is tens of
    milliseconds of CPU under the GIL, and every concurrent request queued
    behind it. The key is each scan directory's name and the size and mtime
    of its two report files, which is a few hundred stat calls.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._body: HistoryBody | None = None
        self._summary: HistoryBody | None = None
        self._payload: dict | None = None
        self._scans: dict[str, HistoryBody] = {}

    def _signature(self) -> tuple:
        entries = []
        try:
            children = sorted(os.scandir(self.root), key=lambda entry: entry.name)
        except FileNotFoundError:
            return ()
        for entry in children:
            if not entry.is_dir():
                continue
            for name in ("checkstead.txt", "dependency-check-report.json"):
                try:
                    info = os.stat(os.path.join(entry.path, name))
                except FileNotFoundError:
                    entries.append((entry.name, name, None))
                    continue
                entries.append((entry.name, name, info.st_size, info.st_mtime_ns))
        return tuple(entries)

    def _refresh(self) -> None:
        """Rebuild everything when a report changed. Call with the lock held."""
        key = self._signature()
        if self._payload is not None and key == self._key:
            return
        payload = history_payload(load_history(self.root))
        raw = json.dumps(payload).encode("utf-8")
        self._body = HistoryBody(raw, gzip.compress(raw, compresslevel=6))
        summary = json.dumps(summarize(payload)).encode("utf-8")
        self._summary = HistoryBody(summary, gzip.compress(summary, compresslevel=6))
        self._payload = payload
        self._scans = {}
        self._key = key

    def body(self) -> HistoryBody:
        """The full history: every scan with every dependency."""
        with self._lock:
            self._refresh()
            assert self._body is not None
            return self._body

    def summary(self) -> HistoryBody:
        """Scans and findings with dependency lists replaced by counts."""
        with self._lock:
            self._refresh()
            assert self._summary is not None
            return self._summary

    def scan(self, scan_id: str) -> HistoryBody | None:
        """One scan in full, with the drift that ends at it. None when unknown."""
        with self._lock:
            self._refresh()
            if scan_id in self._scans:
                return self._scans[scan_id]
            assert self._payload is not None
            scan = next((item for item in self._payload["scans"] if item["id"] == scan_id), None)
            if scan is None:
                return None
            drift = next((item for item in self._payload["drifts"] if item["after"] == scan_id), None)
            raw = json.dumps({"notice": self._payload["notice"], "scan": scan, "drift": drift}).encode("utf-8")
            body = HistoryBody(raw, gzip.compress(raw, compresslevel=6))
            self._scans[scan_id] = body
            return body


def summarize(payload: dict) -> dict:
    """The history without dependency lists, which can run to tens of
    thousands of entries per scan in a JavaScript tree. Counts stay."""
    scans = []
    for scan in payload["scans"]:
        item = {key: value for key, value in scan.items() if key != "dependencies"}
        item["dependencyCount"] = len(scan.get("dependencies") or [])
        scans.append(item)
    drifts = []
    for drift in payload["drifts"]:
        deps = drift["dependencies"]
        item = {key: value for key, value in drift.items() if key != "dependencies"}
        item["dependencyCounts"] = {name: len(deps.get(name) or []) for name in ("added", "removed", "changed")}
        drifts.append(item)
    return {**payload, "scans": scans, "drifts": drifts}


DEFAULT_MAX_CONNECTIONS = 256


def max_connections() -> int:
    raw = os.environ.get("CHECKSTEAD_MAX_CONNECTIONS", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return DEFAULT_MAX_CONNECTIONS


_BUSY = (
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
    b"Retry-After: 1\r\nConnection: close\r\nContent-Length: 39\r\n\r\n"
    b"The server is busy. Try again shortly.\n"
)


class BoundedHTTPServer(ThreadingHTTPServer):
    """One thread per connection, up to a limit. Past it, 503 and close.

    Without a limit a flood of connections, or many idle keep-alive clients,
    grows threads and memory until the process fails for everyone.
    """

    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, handler, limit: int) -> None:
        self._slots = threading.BoundedSemaphore(limit)
        self.max_connections = limit
        super().__init__(address, handler)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(_BUSY)
                # Read what the client already sent before closing. Closing
                # with unread data makes Windows reset the connection, and
                # the client then never sees the 503.
                # This runs on the accept thread, so it is bounded to 100 ms
                # in total however slowly the client sends.
                deadline = time.monotonic() + 0.1
                while (left := deadline - time.monotonic()) > 0:
                    request.settimeout(left)
                    if not request.recv(65536):
                        break
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address) -> None:
        # A client that hangs up or times out is routine, not a server error.
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


STATIC_DIR = Path(__file__).resolve().with_name("static")
STATIC_TYPES = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
    ".txt": "text/plain; charset=utf-8",
}


def static_files(root: Path = STATIC_DIR) -> dict[str, tuple[bytes, str, str]]:
    """Every file the web UI may load, read once at startup.

    A request is answered only when its path is a key here, so no request can
    name a file outside this set. The value is the body, its content type,
    and a strong ETag.
    """
    import hashlib

    files: dict[str, tuple[bytes, str, str]] = {}
    if not root.is_dir():
        return files
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in STATIC_TYPES:
            continue
        body = path.read_bytes()
        key = "/static/" + path.relative_to(root).as_posix()
        files[key] = (body, STATIC_TYPES[path.suffix], '"' + hashlib.sha256(body).hexdigest()[:32] + '"')
    return files


def content_security_policy(legacy: bool = False) -> str:
    """No inline script or style on the app; nothing from another origin.

    ``legacy`` is the server-rendered GitHub App pages, which still carry one
    inline script (the manifest auto-submit) and post their form to the GitHub
    web host.
    """
    from checkstead.identity import github_web_base

    if not legacy:
        return "; ".join(
            [
                "default-src 'none'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "form-action 'self'",
                "frame-ancestors 'none'",
                "base-uri 'none'",
                "object-src 'none'",
            ]
        )
    web = urlsplit(github_web_base())
    github = f"{web.scheme}://{web.netloc}" if web.scheme and web.netloc else "https://github.com"
    return "; ".join(
        [
            "default-src 'none'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "connect-src 'self'",
            f"form-action 'self' {github}",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "object-src 'none'",
        ]
    )


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
    # One repository scan batch at a time. A second request gets 409 instead
    # of a second engine on the same snapshot data directory.
    scan_lock = threading.Lock()
    history = HistoryCache(scans_dir)
    assets = static_files()

    class Handler(BaseHTTPRequestHandler):
        timeout = SOCKET_TIMEOUT_SECONDS
        # Keep-alive. Every response sets Content-Length, and an idle
        # connection is closed after SOCKET_TIMEOUT_SECONDS.
        protocol_version = "HTTP/1.1"

        def _guard(self, unsafe: bool) -> bool:
            """Refuse a foreign Host, and a cross-site state change. True to continue."""
            self._raw: bytes | None = None
            path = self.path.split("?", 1)[0]
            if path in _UNGUARDED_PATHS:
                # No Host or Origin check here, but a body still has to leave
                # the connection. The webhook drains its own.
                if unsafe and path != "/api/github/hook":
                    return self._read_request_body()
                return True
            host = self.headers.get("Host", "")
            if not host_allowed(host):
                # The body, if any, is not read. With keep-alive its bytes would
                # be parsed as the next request, so the connection ends here.
                self.close_connection = True
                self._send(
                    421,
                    "text/plain; charset=utf-8",
                    b"This Checkstead server does not answer to that host name. "
                    b"Add it to CHECKSTEAD_ALLOWED_HOSTS or CHECKSTEAD_PUBLIC_BASE.\n",
                )
                return False
            if unsafe and not origin_allowed(
                self.headers.get("Origin", ""),
                host,
                self.headers.get("Sec-Fetch-Site", ""),
            ):
                self.close_connection = True
                self._json(403, {"error": "Cross-site request refused."})
                return False
            if unsafe:
                return self._read_request_body()
            return True

        def _read_request_body(self) -> bool:
            """Read the whole body once, before any handler runs.

            Every POST, PATCH, and DELETE body is consumed whether or not its
            handler uses it, so the next request on a keep-alive connection
            starts at a request line.
            """
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                length = -1
            if length < 0:
                self.close_connection = True
                self._json(400, {"error": "Request body is not valid."})
                return False
            if length > MAX_BODY:
                self.close_connection = True
                self._json(413, {"error": "Request is too large."})
                return False
            self._raw = self.rfile.read(length) if length else b""
            return True

        def do_GET(self) -> None:
            if not self._guard(False):
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            if path == "/api/health":
                self._json(200, {"ok": True})
                return
            if path in {"/", "/index.html"}:
                self._send(200, "text/html; charset=utf-8", PAGE.read_bytes())
                return
            if path.startswith("/static/"):
                self._static(path)
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
            if path.startswith("/api/users/") and path.endswith("/avatar"):
                self._avatar(path)
                return
            if path == "/api/history":
                if self._user() is None:
                    return
                self._history(history.body())
                return
            if path == "/api/history/summary":
                if self._user() is None:
                    return
                self._history(history.summary())
                return
            if path.startswith("/api/scans/"):
                if self._user() is None:
                    return
                scan_body = history.scan(unquote(path[len("/api/scans/"):]))
                if scan_body is None:
                    self._json(404, {"error": "There is no scan with that name."})
                    return
                self._history(scan_body)
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
            if not self._guard(True):
                return
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
            if not self._guard(True):
                return
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
            if not self._guard(True):
                return
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
            self.send_header("Content-Length", "0")
            self._common_headers()
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
            self.send_header("Content-Length", "0")
            self._common_headers()
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
            """GitHub App administration. A loopback peer needs no session only on a laptop.

            With ``CHECKSTEAD_LOCAL`` set to anything, the server is behind
            Docker or a reverse proxy, and a loopback peer can be every remote
            client. Those deployments need an administrator session.
            """
            if not os.environ.get("CHECKSTEAD_LOCAL", "").strip() and localhost_client(
                self.client_address[0]
            ):
                return True
            return self._admin() is not None

        def _github_hook(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length < 0 or length > 1024 * 1024:
                # Not drained in full, so the connection cannot be reused.
                self.close_connection = True
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
            if not scan_lock.acquire(blocking=False):
                message = "A scan is already running. Try again when it finishes."
                if self._wants_json():
                    self._json(409, {"error": message})
                else:
                    self._html(409, render_message("Scan", [message]))
                return
            try:
                self._github_scan_locked()
            finally:
                scan_lock.release()

        def _github_scan_locked(self) -> None:
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
            # _guard read and size-checked the body before the handler ran.
            raw = self._raw or b""
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
            legacy = self.path.split("?", 1)[0].startswith(("/github", "/api/github/"))
            self.send_header("Content-Security-Policy", content_security_policy(legacy))
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            if self.close_connection:
                self.send_header("Connection", "close")
            if not self.path.startswith("/static/") and not _AVATAR_PATH.fullmatch(
                self.path.split("?", 1)[0]
            ):
                self.send_header("Cache-Control", "no-store")
            if os.environ.get("CHECKSTEAD_COOKIE_SECURE") == "1":
                self.send_header("Strict-Transport-Security", "max-age=31536000")

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
            # _guard read and size-checked the body before the handler ran.
            raw = self._raw or b""
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

        def _static(self, path: str) -> None:
            found = assets.get(path)
            if found is None:
                self._send(404, "text/plain; charset=utf-8", b"Not found\n")
                return
            body, content_type, etag = found
            # Revalidate every time: an upgrade must never leave an old script
            # running against a new API.
            if self.headers.get("If-None-Match") == etag:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", "0")
                self._common_headers()
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "no-cache")
            self._common_headers()
            self.end_headers()
            self.wfile.write(body)

        def _avatar(self, path: str) -> None:
            match = _AVATAR_PATH.fullmatch(path)
            if match is None:
                self._send(404, "text/plain; charset=utf-8", b"Not found\n")
                return
            if self._user() is None:
                return
            found = store.avatar(int(match.group(1)))
            if found is None:
                self._send(404, "text/plain; charset=utf-8", b"Not found\n")
                return
            self.send_response(200)
            self.send_header("Content-Type", found.mime)
            self.send_header("Content-Length", str(len(found.data)))
            # The URL carries the picture's hash, so a new picture is a new URL.
            self.send_header("Cache-Control", "private, max-age=604800, immutable")
            self.send_header("Content-Disposition", "inline")
            self._common_headers()
            self.end_headers()
            self.wfile.write(found.data)

        def _history(self, body: HistoryBody) -> None:
            compressed = "gzip" in self.headers.get("Accept-Encoding", "")
            data = body.gzipped if compressed else body.raw
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Vary", "Accept-Encoding")
            if compressed:
                self.send_header("Content-Encoding", "gzip")
            self._common_headers()
            self.end_headers()
            self.wfile.write(data)

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

    return BoundedHTTPServer((host, port), Handler, max_connections())


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
    warn_entra_tenant()
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
