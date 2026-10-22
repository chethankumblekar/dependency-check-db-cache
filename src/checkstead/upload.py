"""A pipeline sends its report folder to the server.

The body is a zip of the report files. Only the files a scan writes are kept,
only at the top level, and only up to a size limit. The server never runs or
extracts anything else from it.
"""

from __future__ import annotations

import io
import os
import re
import secrets
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from checkstead.errors import ChecksteadError
from checkstead.history import parse_header
from checkstead.origin import parse_repository_url

REPORT = "checkstead.txt"
REPORT_FILES = (
    REPORT,
    "dependency-check-report.json",
    "dependency-check-report.html",
    "checkstead.sarif",
    "checkstead-comment.md",
    "checkstead-command.txt",
)
_SLUG = re.compile(r"[^a-z0-9]+")


def max_upload_bytes() -> int:
    raw = os.environ.get("CHECKSTEAD_MAX_UPLOAD_MB", "").strip()
    megabytes = int(raw) if raw.isdigit() and int(raw) > 0 else 64
    return megabytes * 1024 * 1024


class UploadError(ChecksteadError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def _slug(value: str | None) -> str:
    return _SLUG.sub("-", (value or "").lower()).strip("-")[:60] or "scan"


def _member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    name = info.filename
    if name not in REPORT_FILES:
        raise UploadError(f"The upload contains {name!r}, which is not a Checkstead report file.")
    if (info.external_attr >> 16) & 0o170000 == 0o120000:
        raise UploadError(f"{name} is a symbolic link.")
    if info.file_size > limit:
        raise UploadError(f"{name} is larger than this server accepts.", 413)
    with archive.open(info) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise UploadError(f"{name} is larger than this server accepts.", 413)
    return data


def read_report_zip(body: bytes) -> dict[str, bytes]:
    """The report files in ``body``, by name. Anything unexpected is refused."""
    limit = max_upload_bytes()
    try:
        archive = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile as exc:
        raise UploadError("The upload is not a zip of a Checkstead report folder.") from exc
    with archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > 32:
            raise UploadError("The upload has more files than a report folder.")
        if sum(max(info.file_size, 0) for info in infos) > limit * 4:
            raise UploadError("The upload expands to more than this server accepts.", 413)
        files = {info.filename: _member(archive, info, limit) for info in infos}
    if REPORT not in files:
        raise UploadError(f"The upload has no {REPORT}. Upload the folder `checkstead scan --out` wrote.")
    try:
        header = parse_header(files[REPORT].decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise UploadError(f"{REPORT} is not text.") from exc
    if not header.get("engine") or not header.get("snapshot"):
        raise UploadError("checkstead.txt is not a Checkstead report: it names no engine or snapshot.")
    return files


def report_zip(report_dir: Path) -> bytes:
    """Zip the report files present in ``report_dir``. checkstead.txt is required."""
    if not (report_dir / REPORT).is_file():
        raise ChecksteadError(f"{report_dir} has no {REPORT}. Pass the folder `checkstead scan --out` wrote.")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in REPORT_FILES:
            path = report_dir / name
            if path.is_file() and not path.is_symlink():
                archive.write(path, name)
    return buffer.getvalue()


def send_report(server: str, report_dir: Path, token: str, opener=None) -> dict:
    """POST the report to ``server``. The token comes from the caller, never argv."""
    import json
    import urllib.error
    import urllib.request

    from checkstead.http import USER_AGENT, build_opener, ensure_allowed

    if not token:
        raise ChecksteadError("Set CHECKSTEAD_UPLOAD_TOKEN to an upload token from the server's Access page.")
    base = server.strip().rstrip("/")
    url = f"{base}/api/scans/upload"
    ensure_allowed(url)
    body = report_zip(report_dir)
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/zip",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with (opener or build_opener()).open(request, timeout=300) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        try:
            message = json.loads(detail).get("error") or detail
        except ValueError:
            message = detail
        raise ChecksteadError(f"The server refused the report: HTTP {exc.code}. {message}") from exc
    except urllib.error.URLError as exc:
        raise ChecksteadError(f"The server could not be reached: {exc.reason}") from exc
    payload["url"] = f"{base}{payload.get('url', '')}"
    return payload


def store_upload(body: bytes, scans_dir: Path, token_id: int) -> str:
    """Write the report into a new scan folder and return its id."""
    files = read_report_zip(body)
    header = parse_header(files[REPORT].decode("utf-8"))
    origin = parse_repository_url(header.get("repository-url"))
    name = origin.repository if origin else header.get("project")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    scan_id = f"{stamp}-{_slug(name)}-t{token_id}-{secrets.token_hex(3)}"
    scans_dir.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".upload-", dir=scans_dir))
    try:
        for file_name, data in files.items():
            (staging / file_name).write_bytes(data)
        staging.replace(scans_dir / scan_id)
    except OSError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return scan_id
