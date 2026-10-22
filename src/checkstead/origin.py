"""Where a scan came from: the repository and the build that ran it.

A pipeline passes its own predefined variables (Build.Repository.Uri and the
build's web link). The server groups scans by organization, project,
repository, and branch from these, the way SonarQube learns a repository from
the analyses its pipelines send. A scan without them came from a checkout,
not a pipeline, and is not listed under Repositories.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

_SEGMENT = re.compile(r"^[^\s/\\?#]{1,200}$")


def clean_url(value: str | None) -> str | None:
    """An https URL without credentials, query, or fragment, else None.

    Build.Repository.Uri often carries the organization as userinfo
    (https://Ascertra@dev.azure.com/...). That part is dropped, never stored.
    """
    if not value:
        return None
    text = value.strip()
    if not text or len(text) > 2000 or any(char in text for char in "\r\n\x00 "):
        return None
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit(("https", host + port, parsed.path.rstrip("/"), "", ""))


def build_link(value: str | None) -> str | None:
    """Like clean_url, but keeps the query: an Azure DevOps build link is ?buildId=N."""
    if not value:
        return None
    text = value.strip()
    if not text or len(text) > 2000 or any(char in text for char in "\r\n\x00 "):
        return None
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit(("https", host + port, parsed.path, parsed.query, ""))


@dataclass(frozen=True)
class Origin:
    provider: str  # "azure-devops", "github", or "git"
    organization: str
    project: str | None
    repository: str
    url: str


def _strip_git(name: str) -> str:
    return name[:-4] if name.endswith(".git") else name


def _azure(host: str, parts: list[str], url: str) -> Origin | None:
    if host == "dev.azure.com":
        if len(parts) == 4 and parts[2] == "_git":
            return Origin("azure-devops", parts[0], parts[1], parts[3], url)
        return None
    organization = host[: -len(".visualstudio.com")]
    if parts[:1] == ["DefaultCollection"]:
        parts = parts[1:]
    if len(parts) == 3 and parts[1] == "_git":
        return Origin("azure-devops", organization, parts[0], parts[2], url)
    if len(parts) == 2 and parts[0] == "_git":
        # A repository named like its project: /_git/<repo>.
        return Origin("azure-devops", organization, parts[1], parts[1], url)
    return None


def parse_repository_url(value: str | None) -> Origin | None:
    url = clean_url(value)
    if url is None:
        return None
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if not parts or not all(_SEGMENT.fullmatch(part) for part in parts):
        return None
    if host == "dev.azure.com" or host.endswith(".visualstudio.com"):
        return _azure(host, parts, url)
    if host == "github.com":
        if len(parts) != 2:
            return None
        repository = _strip_git(parts[1])
        return Origin("github", parts[0], None, repository, f"https://github.com/{parts[0]}/{repository}")
    return Origin("git", host, "/".join(parts[:-1]) or None, _strip_git(parts[-1]), url)
