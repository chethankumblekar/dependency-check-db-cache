"""What every repository source returns, whichever Git host it reads.

A source is an organization-level connection that the server holds itself:
the GitHub App installation, or an Azure DevOps organization the server's
service principal belongs to. Nobody pastes a token for it.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol

from checkstead.errors import ChecksteadError
from checkstead.http import USER_AGENT, build_opener, ensure_allowed

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 30

# (method, url, headers, body) -> (status, response headers, body)
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, dict[str, str], bytes]]


class SourceError(ChecksteadError):
    """The Git host refused or could not answer. The message is safe to show."""


@dataclass(frozen=True)
class Branch:
    name: str
    commit: str | None = None


@dataclass(frozen=True)
class Repository:
    source: str
    id: str
    name: str
    project: str | None = None
    url: str | None = None
    default_branch: str | None = None
    disabled: bool = False
    branches: tuple[Branch, ...] = field(default_factory=tuple)

    @property
    def scan_names(self) -> tuple[str, ...]:
        """Names a scan of this repository may carry as its project."""
        names = [self.name]
        if self.project:
            names.append(f"{self.project}/{self.name}")
        return tuple(names)

    def to_json(self) -> dict:
        data = asdict(self)
        data["defaultBranch"] = data.pop("default_branch")
        data["branches"] = [asdict(item) for item in self.branches]
        return data


@dataclass(frozen=True)
class PipelineRun:
    source: str
    id: str
    repository: str | None
    project: str | None
    pipeline: str | None
    status: str
    result: str | None
    branch: str | None
    url: str | None
    queued_at: str | None
    finished_at: str | None

    def to_json(self) -> dict:
        data = asdict(self)
        data["queuedAt"] = data.pop("queued_at")
        data["finishedAt"] = data.pop("finished_at")
        return data


class Source(Protocol):
    kind: str
    label: str

    def configured(self) -> bool: ...

    def list_repositories(self, include_branches: bool) -> list[Repository]: ...

    def list_runs(self) -> list[PipelineRun]: ...


def default_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, dict[str, str], bytes]:
    ensure_allowed(url)
    request = urllib.request.Request(
        url, data=body, method=method, headers={**headers, "User-Agent": USER_AGENT}
    )
    try:
        with build_opener().open(request, timeout=TIMEOUT_SECONDS) as response:
            ensure_allowed(response.geturl())
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status, reply = response.status, {k.lower(): v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read(64 * 1024)
    except ChecksteadError:
        raise
    except Exception as exc:
        raise SourceError(f"{urllib.parse.urlparse(url).hostname} could not be reached.") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SourceError("The Git host sent a response larger than Checkstead reads.")
    return status, reply, raw


def json_object(status: int, body: bytes, failure: str) -> dict:
    if status == 401:
        raise SourceError(f"{failure} The server's credential was refused (HTTP 401).")
    if status == 403:
        raise SourceError(f"{failure} The server's identity lacks permission (HTTP 403).")
    if status != 200:
        raise SourceError(f"{failure} HTTP {status}.")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SourceError(f"{failure} The answer was not JSON.") from exc
    if not isinstance(payload, dict):
        raise SourceError(f"{failure} The answer was not a JSON object.")
    return payload


def clean_text(value: object, limit: int = 200) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > limit or any(char in cleaned for char in "\r\n\x00"):
        return None
    return cleaned


def branch_name(ref: object) -> str | None:
    """refs/heads/main -> main. Anything else, or an unsafe name, is None."""
    cleaned = clean_text(ref, 300)
    if cleaned is None or not cleaned.startswith("refs/heads/"):
        return None
    name = cleaned[len("refs/heads/") :]
    return name or None
