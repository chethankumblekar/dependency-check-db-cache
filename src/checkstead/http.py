from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import certifi

from checkstead import __version__
from checkstead.errors import RefusedHost

USER_AGENT = f"checkstead/{__version__}"
BLOCKED_HOSTS = frozenset({"services.nvd.nist.gov", "metadata.google.internal", "metadata.goog"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
READ_TIMEOUT_SECONDS = 120
# A manifest is a few hundred bytes. Anything near this is not a manifest.
MAX_TEXT_BYTES = 1024 * 1024
# 408, 425, 429, and 5xx are worth another attempt. 4xx otherwise is final.
RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


def _blocked_address(host: str) -> bool:
    """Link-local, multicast, and unspecified addresses are not snapshot hosts.

    Loopback stays allowed so tests can serve fixtures. Private addresses stay
    allowed so a GitHub Enterprise host on an internal network still works.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if address.is_loopback:
        return False
    return bool(address.is_link_local or address.is_multicast or address.is_unspecified)


def ensure_allowed(url: str) -> None:
    """Reject the NVD API host, and cleartext HTTP to anything but loopback.

    Tests serve fixtures on 127.0.0.1. A published snapshot is https. file://
    is not a download location this client accepts.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"}:
        raise RefusedHost(f"Refusing URL scheme '{parsed.scheme or ''}'.")
    if parsed.username or parsed.password:
        raise RefusedHost("Refusing a URL that contains userinfo.")
    host = (parsed.hostname or "").rstrip(".").lower()
    if host.isdigit() or _blocked_address(host):
        raise RefusedHost(f"Refusing host '{host}'.")
    if parsed.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise RefusedHost(
            "Refusing cleartext HTTP except to localhost. Use an https snapshot URL."
        )
    if host in BLOCKED_HOSTS:
        raise RefusedHost(
            "Refusing to contact services.nvd.nist.gov. "
            "The scan uses a published snapshot and --noupdate."
        )


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Check every redirect target, and drop credentials when the host changes.

    urllib copies request headers onto the redirected request. A GitHub
    zipball redirects to a download host, and a token for the API host must
    not travel to whatever host the redirect names.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ensure_allowed(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is None:
            return None
        before = (urlparse(req.full_url).hostname or "").lower()
        after = (urlparse(newurl).hostname or "").lower()
        if before != after:
            for name in ("Authorization", "Cookie", "Proxy-Authorization"):
                redirected.remove_header(name)
                redirected.unredirected_hdrs.pop(name, None)
        return redirected


def _attempts() -> int:
    raw = os.environ.get("CHECKSTEAD_HTTP_ATTEMPTS", "").strip()
    if raw.isdigit() and 1 <= int(raw) <= 10:
        return int(raw)
    return 4


def _retryable(exc: BaseException) -> bool:
    if isinstance(exc, RefusedHost):
        return False
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRY_STATUS
    return isinstance(exc, (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError))


def with_retries(action, what: str, sleep=None):
    """Run ``action`` and retry a transient network failure with exponential backoff.

    The last failure is raised unchanged, so callers keep their error messages.
    """
    attempts = _attempts()
    for attempt in range(1, attempts + 1):
        try:
            return action()
        except Exception as exc:
            if attempt >= attempts or not _retryable(exc):
                raise
            delay = min(2 ** (attempt - 1), 30)
            print(
                f"checkstead: {what} failed ({exc}). Retrying in {delay}s, "
                f"attempt {attempt + 1} of {attempts}.",
                file=sys.stderr,
            )
            (sleep or time.sleep)(delay)
    raise AssertionError("unreachable")


def build_opener() -> urllib.request.OpenerDirector:
    """Trust the certifi CA bundle. python.org macOS builds ship without one."""
    context = ssl.create_default_context(cafile=certifi.where())
    return urllib.request.build_opener(
        _GuardedRedirectHandler,
        urllib.request.HTTPSHandler(context=context),
    )


def download(
    url: str,
    dest: Path,
    opener: urllib.request.OpenerDirector | None = None,
    headers: dict[str, str] | None = None,
) -> str:
    """Stream a URL to disk and return the SHA-256 hex digest. Never calls the NVD API.

    A transient failure is retried from the start of the file.
    """
    ensure_allowed(url)
    return with_retries(lambda: _download_once(url, dest, opener, headers), f"Download of {url}")


def _download_once(
    url: str,
    dest: Path,
    opener: urllib.request.OpenerDirector | None,
    headers: dict[str, str] | None,
) -> str:
    opener = opener or build_opener()
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    request = urllib.request.Request(url, headers=request_headers)
    digest = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix(dest.suffix + ".partial")
    try:
        with opener.open(request, timeout=READ_TIMEOUT_SECONDS) as response:
            ensure_allowed(response.geturl())
            with temporary.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                    digest.update(chunk)
        temporary.replace(dest)
    except RefusedHost:
        temporary.unlink(missing_ok=True)
        raise
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return digest.hexdigest()


def read_text(url: str, opener: urllib.request.OpenerDirector | None = None) -> str:
    """Fetch a small text document, at most MAX_TEXT_BYTES, with retries."""
    ensure_allowed(url)

    def once() -> str:
        active = opener or build_opener()
        request = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        with active.open(request, timeout=READ_TIMEOUT_SECONDS) as response:
            ensure_allowed(response.geturl())
            body = response.read(MAX_TEXT_BYTES + 1)
        if len(body) > MAX_TEXT_BYTES:
            raise RefusedHost(f"Refusing a response larger than {MAX_TEXT_BYTES} bytes from {url}.")
        return body.decode("utf-8")

    return with_retries(once, f"Request for {url}")
