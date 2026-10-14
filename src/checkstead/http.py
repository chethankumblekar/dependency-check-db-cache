from __future__ import annotations

import hashlib
import ssl
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import certifi

from checkstead import __version__
from checkstead.errors import RefusedHost

USER_AGENT = f"checkstead/{__version__}"
BLOCKED_HOSTS = frozenset({"services.nvd.nist.gov"})
READ_TIMEOUT_SECONDS = 120


def ensure_allowed(url: str) -> None:
    """Reject the NVD API host before any connection to it."""
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http", "file"}:
        raise RefusedHost(f"Refusing URL scheme '{parsed.scheme or ''}'.")
    host = (parsed.hostname or "").rstrip(".").lower()
    if host in BLOCKED_HOSTS:
        raise RefusedHost(
            "Refusing to contact services.nvd.nist.gov. "
            "The scan uses a published snapshot and --noupdate."
        )


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        ensure_allowed(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def build_opener() -> urllib.request.OpenerDirector:
    """Trust the certifi CA bundle. python.org macOS builds ship without one."""
    context = ssl.create_default_context(cafile=certifi.where())
    return urllib.request.build_opener(
        _GuardedRedirectHandler,
        urllib.request.HTTPSHandler(context=context),
    )


def download(url: str, dest: Path, opener: urllib.request.OpenerDirector | None = None) -> str:
    """Stream a URL to disk and return the SHA-256 hex digest. Never calls the NVD API."""
    ensure_allowed(url)
    opener = opener or build_opener()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
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
    ensure_allowed(url)
    opener = opener or build_opener()
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    with opener.open(request, timeout=READ_TIMEOUT_SECONDS) as response:
        ensure_allowed(response.geturl())
        return response.read().decode("utf-8")
