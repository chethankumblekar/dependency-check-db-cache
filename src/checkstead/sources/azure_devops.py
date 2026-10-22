"""An Azure DevOps organization, read by the server's own service principal.

An organization administrator adds the Microsoft Entra application to the
organization as a user and gives it Reader on the projects to show. The
server gets a token for Azure DevOps with that application's client
credentials. No person's token is used or stored.

    CHECKSTEAD_AZURE_DEVOPS_ORG            organization name (dev.azure.com/<org>)
    CHECKSTEAD_AZURE_DEVOPS_PROJECTS       optional, comma-separated project names
    CHECKSTEAD_AZURE_DEVOPS_PIPELINES      pipeline name filter, default *checkstead*
    CHECKSTEAD_AZURE_DEVOPS_CLIENT_ID      default CHECKSTEAD_ENTRA_CLIENT_ID
    CHECKSTEAD_AZURE_DEVOPS_CLIENT_SECRET  default CHECKSTEAD_ENTRA_CLIENT_SECRET
    CHECKSTEAD_AZURE_DEVOPS_TENANT         default CHECKSTEAD_ENTRA_TENANT (a tenant id)
"""

from __future__ import annotations

import os
import re
import threading
import time
import urllib.parse

from checkstead.identity import azure_api_base
from checkstead.sources.base import (
    Branch,
    PipelineRun,
    Repository,
    SourceError,
    Transport,
    branch_name,
    clean_text,
    default_transport,
    json_object,
)

# The Azure DevOps resource. Its .default scope is what a service principal asks for.
AZURE_DEVOPS_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798"
API_VERSION = "7.1"
_ORG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_PIPELINE_FILTER = re.compile(r"^[A-Za-z0-9 _.*-]{1,100}$")
_MAX_PAGES = 50


def _env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


class AzureDevOpsSource:
    kind = "azure-devops"

    def __init__(self, transport: Transport | None = None) -> None:
        self.transport = transport or default_transport
        self._lock = threading.Lock()
        self._token: tuple[str, float] | None = None

    # -- configuration -------------------------------------------------------

    @property
    def organization(self) -> str:
        return _env("CHECKSTEAD_AZURE_DEVOPS_ORG")

    @property
    def label(self) -> str:
        return f"Azure DevOps: {self.organization}" if self.organization else "Azure DevOps"

    def configured(self) -> bool:
        return bool(
            self.organization
            and _env("CHECKSTEAD_AZURE_DEVOPS_CLIENT_ID", "CHECKSTEAD_ENTRA_CLIENT_ID")
            and _env("CHECKSTEAD_AZURE_DEVOPS_CLIENT_SECRET", "CHECKSTEAD_ENTRA_CLIENT_SECRET")
            and _env("CHECKSTEAD_AZURE_DEVOPS_TENANT", "CHECKSTEAD_ENTRA_TENANT")
        )

    def _check(self) -> str:
        org = self.organization
        if not _ORG.fullmatch(org):
            raise SourceError("CHECKSTEAD_AZURE_DEVOPS_ORG is not an Azure DevOps organization name.")
        tenant = _env("CHECKSTEAD_AZURE_DEVOPS_TENANT", "CHECKSTEAD_ENTRA_TENANT")
        if not _GUID.fullmatch(tenant):
            # organizations/common cannot issue an app-only token.
            raise SourceError("The Azure DevOps source needs a directory (tenant) id, not organizations or common.")
        if not _PIPELINE_FILTER.fullmatch(self._pipeline_filter()):
            raise SourceError("CHECKSTEAD_AZURE_DEVOPS_PIPELINES is not a pipeline name filter.")
        return org

    def _projects_wanted(self) -> frozenset[str] | None:
        raw = _env("CHECKSTEAD_AZURE_DEVOPS_PROJECTS")
        if not raw:
            return None
        return frozenset(item.strip().casefold() for item in raw.split(",") if item.strip())

    def _pipeline_filter(self) -> str:
        return _env("CHECKSTEAD_AZURE_DEVOPS_PIPELINES") or "*checkstead*"

    # -- HTTP ----------------------------------------------------------------

    def _access_token(self) -> str:
        with self._lock:
            if self._token and self._token[1] - 120 > time.time():
                return self._token[0]
            tenant = _env("CHECKSTEAD_AZURE_DEVOPS_TENANT", "CHECKSTEAD_ENTRA_TENANT")
            url = _env("CHECKSTEAD_AZURE_DEVOPS_TOKEN") or (
                f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            )
            body = urllib.parse.urlencode(
                {
                    "client_id": _env("CHECKSTEAD_AZURE_DEVOPS_CLIENT_ID", "CHECKSTEAD_ENTRA_CLIENT_ID"),
                    "client_secret": _env("CHECKSTEAD_AZURE_DEVOPS_CLIENT_SECRET", "CHECKSTEAD_ENTRA_CLIENT_SECRET"),
                    "grant_type": "client_credentials",
                    "scope": f"{AZURE_DEVOPS_RESOURCE}/.default",
                }
            ).encode("ascii")
            status, _headers, raw = self.transport(
                "POST",
                url,
                {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
                body,
            )
            if status in {400, 401}:
                raise SourceError(
                    "Microsoft Entra refused the server's client credentials for Azure DevOps "
                    f"(HTTP {status}). Check the client id, secret, and tenant."
                )
            payload = json_object(status, raw, "Microsoft Entra did not issue an Azure DevOps token.")
            token = payload.get("access_token")
            if not isinstance(token, str) or not token:
                raise SourceError("Microsoft Entra did not issue an Azure DevOps token.")
            lifetime = payload.get("expires_in")
            seconds = int(lifetime) if isinstance(lifetime, (int, str)) and str(lifetime).isdigit() else 600
            self._token = (token, time.time() + seconds)
            return token

    def _get(self, path: str, query: dict[str, str], failure: str) -> tuple[dict, str | None]:
        org = self._check()
        params = {**query, "api-version": API_VERSION}
        url = f"{azure_api_base()}/{urllib.parse.quote(org)}/{path}?{urllib.parse.urlencode(params)}"
        status, headers, raw = self.transport(
            "GET", url, {"Accept": "application/json", "Authorization": f"Bearer {self._access_token()}"}, None
        )
        if status in {203, 302, 401}:
            # An identity the organization does not know gets 401 (TF400813), or a
            # sign-in page on older endpoints. Either way the fix is in the org.
            raise SourceError(
                f"{failure} The service principal is not a user in the {org} organization, "
                "or has no access there. An organization administrator adds it under "
                "Organization settings > Users."
            )
        payload = json_object(status, raw, failure)
        return payload, clean_text(headers.get("x-ms-continuationtoken"), 2000)

    def _get_all(self, path: str, query: dict[str, str], failure: str) -> list[dict]:
        items: list[dict] = []
        token: str | None = None
        for _page in range(_MAX_PAGES):
            page_query = dict(query)
            if token:
                page_query["continuationToken"] = token
            payload, token = self._get(path, page_query, failure)
            values = payload.get("value")
            if not isinstance(values, list):
                raise SourceError(f"{failure} The answer had no list.")
            items.extend(item for item in values if isinstance(item, dict))
            if not token:
                break
        return items

    # -- reads ---------------------------------------------------------------

    def _projects(self) -> list[dict]:
        projects = self._get_all(
            "_apis/projects", {"$top": "200", "stateFilter": "wellFormed"}, "Azure DevOps did not list projects."
        )
        wanted = self._projects_wanted()
        found = []
        for project in projects:
            name = clean_text(project.get("name"))
            ident = project.get("id")
            if not name or not isinstance(ident, str) or not _GUID.fullmatch(ident):
                continue
            if wanted is not None and name.casefold() not in wanted:
                continue
            found.append({"id": ident, "name": name})
        return sorted(found, key=lambda item: item["name"].casefold())

    def list_repositories(self, include_branches: bool = True) -> list[Repository]:
        repositories: list[Repository] = []
        for project in self._projects():
            items = self._get_all(
                f"{project['id']}/_apis/git/repositories",
                {},
                f"Azure DevOps did not list the repositories in {project['name']}.",
            )
            for item in items:
                ident = item.get("id")
                name = clean_text(item.get("name"))
                if not isinstance(ident, str) or not _GUID.fullmatch(ident) or not name:
                    continue
                disabled = bool(item.get("isDisabled"))
                branches: tuple[Branch, ...] = ()
                if include_branches and not disabled and item.get("size") != 0:
                    branches = self._branches(project, ident, name)
                repositories.append(
                    Repository(
                        source=self.kind,
                        id=ident,
                        name=name,
                        project=project["name"],
                        url=_https(item.get("webUrl")),
                        default_branch=branch_name(item.get("defaultBranch")),
                        disabled=disabled,
                        branches=branches,
                    )
                )
        return sorted(repositories, key=lambda repo: ((repo.project or "").casefold(), repo.name.casefold()))

    def _branches(self, project: dict, repository_id: str, name: str) -> tuple[Branch, ...]:
        refs = self._get_all(
            f"{project['id']}/_apis/git/repositories/{repository_id}/refs",
            {"filter": "heads/", "$top": "1000"},
            f"Azure DevOps did not list the branches of {project['name']}/{name}.",
        )
        found = []
        for ref in refs:
            branch = branch_name(ref.get("name"))
            if branch is None:
                continue
            commit = ref.get("objectId")
            found.append(Branch(branch, commit if isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40}", commit) else None))
        return tuple(sorted(found, key=lambda item: item.name.casefold()))

    def list_runs(self, limit: int = 25) -> list[PipelineRun]:
        runs: list[PipelineRun] = []
        for project in self._projects():
            definitions = self._get_all(
                f"{project['id']}/_apis/build/definitions",
                {"name": self._pipeline_filter()},
                f"Azure DevOps did not list the pipelines in {project['name']}.",
            )
            ids = [str(item["id"]) for item in definitions if isinstance(item.get("id"), int)]
            if not ids:
                continue
            payload, _token = self._get(
                f"{project['id']}/_apis/build/builds",
                {"definitions": ",".join(ids[:100]), "$top": str(limit), "queryOrder": "queueTimeDescending"},
                f"Azure DevOps did not list the pipeline runs in {project['name']}.",
            )
            for item in payload.get("value") or []:
                if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                    continue
                repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
                definition = item.get("definition") if isinstance(item.get("definition"), dict) else {}
                links = item.get("_links") if isinstance(item.get("_links"), dict) else {}
                web = links.get("web") if isinstance(links.get("web"), dict) else {}
                runs.append(
                    PipelineRun(
                        source=self.kind,
                        id=str(item["id"]),
                        repository=clean_text(repository.get("name")),
                        project=project["name"],
                        pipeline=clean_text(definition.get("name")),
                        status=clean_text(item.get("status"), 40) or "unknown",
                        result=clean_text(item.get("result"), 40),
                        branch=branch_name(item.get("sourceBranch")) or clean_text(item.get("sourceBranch")),
                        url=_https(web.get("href")),
                        queued_at=clean_text(item.get("queueTime"), 40),
                        finished_at=clean_text(item.get("finishTime"), 40),
                    )
                )
        runs.sort(key=lambda run: run.queued_at or "", reverse=True)
        return runs[:limit]


def _https(value: object) -> str | None:
    cleaned = clean_text(value, 2000)
    if cleaned is None:
        return None
    parsed = urllib.parse.urlparse(cleaned)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return cleaned
