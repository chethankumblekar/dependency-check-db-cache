"""The installed GitHub App, as a repository source.

Repositories, default branches, and workflow runs come from the existing
GitHub App code. This module adds branch listing and the common shape.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path

from checkstead.errors import ChecksteadError
from checkstead.github_app import (
    _REPO,
    _api_headers,
    _installation_token,
    _installed,
    github_request,
    list_repositories,
    list_workflow_runs,
)
from checkstead.identity import github_api_base, github_web_base
from checkstead.sources.base import Branch, PipelineRun, Repository, SourceError, clean_text

_SHA = re.compile(r"^[0-9a-f]{40}$")


def _branch(item: object) -> Branch | None:
    if not isinstance(item, dict):
        return None
    name = clean_text(item.get("name"), 250)
    if not name:
        return None
    commit = item.get("commit") if isinstance(item.get("commit"), dict) else {}
    sha = commit.get("sha")
    return Branch(name, sha if isinstance(sha, str) and _SHA.fullmatch(sha) else None)


class GitHubAppSource:
    kind = "github"
    label = "GitHub"

    def __init__(self, data_dir: Path, transport=None) -> None:
        self.data_dir = data_dir
        self.transport = transport

    def configured(self) -> bool:
        return _installed(self.data_dir)

    def list_repositories(self, include_branches: bool = True) -> list[Repository]:
        try:
            _installation, token = _installation_token(self.data_dir, self.transport)
            names = list_repositories(token, self.transport)
        except ChecksteadError as exc:
            raise SourceError(str(exc)) from exc
        web = github_web_base()
        repositories = []
        for full_name, default_branch in names:
            if not _REPO.fullmatch(full_name):
                continue
            owner, _name = full_name.split("/", 1)
            branches = self._branches(token, full_name) if include_branches else ()
            repositories.append(
                Repository(
                    source=self.kind,
                    id=full_name,
                    name=full_name,
                    project=owner,
                    url=f"{web}/{full_name}",
                    default_branch=default_branch,
                    branches=branches,
                )
            )
        return sorted(repositories, key=lambda repo: repo.name.casefold())

    def _branches(self, token: str, full_name: str) -> tuple[Branch, ...]:
        owner, repo = full_name.split("/", 1)
        found: list[Branch] = []
        for page in range(1, 51):
            status, body = github_request(
                "GET",
                f"{github_api_base()}/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
                f"/branches?per_page=100&page={page}",
                _api_headers(token),
                None,
                self.transport,
            )
            if status != 200:
                raise SourceError(f"GitHub did not list the branches of {full_name} (HTTP {status}).")
            try:
                batch = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise SourceError(f"GitHub did not list the branches of {full_name}.") from exc
            if not isinstance(batch, list):
                raise SourceError(f"GitHub did not list the branches of {full_name}.")
            found.extend(branch for branch in map(_branch, batch) if branch is not None)
            if len(batch) < 100:
                break
        return tuple(sorted(found, key=lambda item: item.name.casefold()))

    def list_runs(self) -> list[PipelineRun]:
        try:
            payload = list_workflow_runs(self.data_dir, self.transport)
        except ChecksteadError as exc:
            raise SourceError(str(exc)) from exc
        runs = []
        for item in payload.get("runs") or []:
            if not isinstance(item, dict):
                continue
            repository = clean_text(item.get("repository"))
            runs.append(
                PipelineRun(
                    source=self.kind,
                    id=str(item.get("id")),
                    repository=repository,
                    project=repository.split("/", 1)[0] if repository else None,
                    pipeline=clean_text(item.get("name")),
                    status=clean_text(item.get("status"), 40) or "unknown",
                    result=None,
                    branch=clean_text(item.get("branch"), 250),
                    url=clean_text(item.get("url"), 2000),
                    queued_at=None,
                    finished_at=clean_text(item.get("updatedAt"), 40),
                )
            )
        return runs
