"""Repository sources, the synced inventory, and Entra group access.

A local stand-in plays Microsoft Entra's token endpoint and the Azure DevOps
REST API. No Git host or identity provider is contacted.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase, mock
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.accounts import AccountError, AccountStore  # noqa: E402
from checkstead.identity import AuthError, Identity  # noqa: E402
from checkstead.sources import Inventory, SourceError  # noqa: E402
from checkstead.sources.azure_devops import AzureDevOpsSource  # noqa: E402
from checkstead.sso import _entra_groups, entra_group_role  # noqa: E402
from checkstead.ui import _policy_fails, bind_server  # noqa: E402

TENANT = "f4ae20ae-32c3-4e78-a38e-01d4426bf0f6"
PROJECT_A = "b6b767a3-4823-41ab-a6b5-09c215ec3c30"
PROJECT_B = "c1c1c1c1-1111-4111-8111-111111111111"
REPO_WEB = "e7e37322-d3f1-4f5f-9f7b-9aa817896c07"
REPO_API = "a2a2a2a2-2222-4222-8222-222222222222"
REPO_EMPTY = "a3a3a3a3-3333-4333-8333-333333333333"
SHA = "0123456789abcdef0123456789abcdef01234567"
ADMINS = "11111111-aaaa-4aaa-8aaa-111111111111"
MEMBERS = "22222222-bbbb-4bbb-8bbb-222222222222"


class _AzureDevOps:
    """Token endpoint and the few Azure DevOps routes the source reads."""

    def __init__(self) -> None:
        outer = self
        self.token_requests: list[dict] = []
        self.api_requests: list[str] = []
        self.api_status = 200

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode())
                outer.token_requests.append({key: value[0] for key, value in form.items()})
                if form.get("client_secret") != ["s3cret"]:
                    return self._send(401, {"error": "invalid_client"})
                self._send(200, {"access_token": "ado-token", "expires_in": 3599, "token_type": "Bearer"})

            def do_GET(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                outer.api_requests.append(parsed.path)
                if self.headers.get("Authorization") != "Bearer ado-token":
                    return self._send(401, {"message": "TF400813"})
                if query.get("api-version") != ["7.1"]:
                    return self._send(400, {"message": "api-version"})
                if outer.api_status != 200:
                    return self._send(outer.api_status, {"message": "TF400813: not authorized"})
                path = parsed.path
                if path == "/acme/_apis/projects":
                    # Two pages, joined by the continuation header.
                    if "continuationToken" not in query:
                        return self._send(200, {"value": [{"id": PROJECT_B, "name": "Tools"}]}, {"x-ms-continuationtoken": "page2"})
                    return self._send(200, {"value": [{"id": PROJECT_A, "name": "Proarc-Products"}]})
                if path == f"/acme/{PROJECT_A}/_apis/git/repositories":
                    return self._send(200, {"value": [
                        {"id": REPO_WEB, "name": "web-app", "defaultBranch": "refs/heads/main",
                         "webUrl": "https://dev.azure.com/acme/Proarc-Products/_git/web-app", "size": 10},
                        {"id": REPO_EMPTY, "name": "empty", "size": 0},
                    ]})
                if path == f"/acme/{PROJECT_B}/_apis/git/repositories":
                    return self._send(200, {"value": [
                        {"id": REPO_API, "name": "api", "defaultBranch": "refs/heads/develop", "isDisabled": True},
                    ]})
                if path == f"/acme/{PROJECT_A}/_apis/git/repositories/{REPO_WEB}/refs":
                    assert query.get("filter") == ["heads/"]
                    return self._send(200, {"value": [
                        {"name": "refs/heads/main", "objectId": SHA},
                        {"name": "refs/heads/feature/x$(touch)", "objectId": SHA},
                        {"name": "refs/tags/v1", "objectId": SHA},
                    ]})
                if path.endswith("/_apis/build/definitions"):
                    assert query.get("name") == ["*checkstead*"]
                    if PROJECT_A in path:
                        return self._send(200, {"value": [{"id": 257, "name": "checkstead-pr"}]})
                    return self._send(200, {"value": []})
                if path == f"/acme/{PROJECT_A}/_apis/build/builds":
                    assert query.get("definitions") == ["257"]
                    return self._send(200, {"value": [{
                        "id": 130078, "status": "completed", "result": "failed",
                        "sourceBranch": "refs/heads/main", "queueTime": "2026-10-22T06:00:00Z",
                        "finishTime": "2026-10-22T06:09:00Z", "repository": {"name": "web-app"},
                        "definition": {"name": "checkstead-pr"},
                        "_links": {"web": {"href": "https://dev.azure.com/acme/x/_build/results?buildId=130078"}},
                    }]})
                self._send(404, {"message": path})

            def _send(self, status, payload, headers=None):
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt, *args):
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        host, port = self._httpd.server_address[:2]
        self.url = f"http://{host}:{port}"

    def env(self) -> dict[str, str]:
        return {
            "CHECKSTEAD_AZURE_DEVOPS_ORG": "acme",
            "CHECKSTEAD_AZURE_DEVOPS_API": self.url,
            "CHECKSTEAD_AZURE_DEVOPS_TOKEN": f"{self.url}/{TENANT}/oauth2/v2.0/token",
            "CHECKSTEAD_ENTRA_CLIENT_ID": "00c96193-57a9-4eec-bb63-7f5e223ebc08",
            "CHECKSTEAD_ENTRA_CLIENT_SECRET": "s3cret",
            "CHECKSTEAD_ENTRA_TENANT": TENANT,
        }

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class AzureDevOpsSourceTests(TestCase):
    def setUp(self) -> None:
        self.ado = _AzureDevOps()
        self.addCleanup(self.ado.close)
        patcher = mock.patch.dict(os.environ, self.ado.env())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_lists_every_project_repository_and_branch_with_one_token(self) -> None:
        source = AzureDevOpsSource()
        self.assertTrue(source.configured())
        self.assertEqual(source.label, "Azure DevOps: acme")
        repos = source.list_repositories(include_branches=True)
        self.assertEqual(
            [(repo.project, repo.name, repo.default_branch, repo.disabled) for repo in repos],
            [("Proarc-Products", "empty", None, False), ("Proarc-Products", "web-app", "main", False), ("Tools", "api", "develop", True)],
        )
        web = repos[1]
        self.assertEqual(web.url, "https://dev.azure.com/acme/Proarc-Products/_git/web-app")
        # A branch name is data, never markup or a command; tags are not branches.
        self.assertEqual([branch.name for branch in web.branches], ["feature/x$(touch)", "main"])
        self.assertEqual(web.branches[1].commit, SHA)
        # Empty and disabled repositories are listed without asking for branches.
        self.assertNotIn(f"/acme/{PROJECT_A}/_apis/git/repositories/{REPO_EMPTY}/refs", self.ado.api_requests)
        self.assertNotIn(f"/acme/{PROJECT_B}/_apis/git/repositories/{REPO_API}/refs", self.ado.api_requests)
        self.assertEqual(len(self.ado.token_requests), 1)
        token = self.ado.token_requests[0]
        self.assertEqual(token["grant_type"], "client_credentials")
        self.assertEqual(token["scope"], "499b84ac-1321-427f-aa17-267ca6975798/.default")

    def test_the_project_filter_limits_what_is_listed(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_AZURE_DEVOPS_PROJECTS": "proarc-products"}):
            repos = AzureDevOpsSource().list_repositories(include_branches=False)
        self.assertEqual({repo.project for repo in repos}, {"Proarc-Products"})

    def test_pipeline_runs_come_from_checkstead_pipelines(self) -> None:
        runs = AzureDevOpsSource().list_runs()
        self.assertEqual(len(runs), 1)
        run = runs[0].to_json()
        self.assertEqual(
            {key: run[key] for key in ("id", "repository", "project", "pipeline", "status", "result", "branch")},
            {"id": "130078", "repository": "web-app", "project": "Proarc-Products", "pipeline": "checkstead-pr",
             "status": "completed", "result": "failed", "branch": "main"},
        )
        self.assertTrue(run["url"].startswith("https://dev.azure.com/"))

    def test_an_unknown_service_principal_is_explained(self) -> None:
        self.ado.api_status = 401
        with self.assertRaises(SourceError) as caught:
            AzureDevOpsSource().list_repositories(include_branches=False)
        self.assertIn("not a user in the acme organization", str(caught.exception))
        self.assertIn("Organization settings > Users", str(caught.exception))

    def test_a_wrong_secret_names_the_credentials_and_not_the_secret(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_ENTRA_CLIENT_SECRET": "wrong-secret"}):
            with self.assertRaises(SourceError) as caught:
                AzureDevOpsSource().list_repositories(include_branches=False)
        self.assertIn("client credentials", str(caught.exception))
        self.assertNotIn("wrong-secret", str(caught.exception))

    def test_a_multi_tenant_setting_cannot_issue_an_app_token(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_ENTRA_TENANT": "organizations"}):
            with self.assertRaises(SourceError) as caught:
                AzureDevOpsSource().list_repositories(include_branches=False)
        self.assertIn("tenant", str(caught.exception))
        self.assertEqual(self.ado.token_requests, [])

    def test_not_configured_without_an_organization(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_AZURE_DEVOPS_ORG": ""}):
            self.assertFalse(AzureDevOpsSource().configured())


class _Failing:
    kind = "azure-devops"
    label = "Azure DevOps: acme"

    def __init__(self) -> None:
        self.fail = False

    def configured(self) -> bool:
        return True

    def list_repositories(self, include_branches: bool):
        if self.fail:
            raise SourceError("Azure DevOps did not list projects. HTTP 503.")
        from checkstead.sources import Repository

        return [Repository(source="azure-devops", id=REPO_WEB, name="web-app", project="Proarc-Products", default_branch="main")]

    def list_runs(self):
        return []


class InventoryTests(TestCase):
    def setUp(self) -> None:
        self.data = ROOT / "build" / "tests" / "inventory" / self.id().split(".")[-1]
        shutil.rmtree(self.data, ignore_errors=True)
        self.data.mkdir(parents=True)

    def test_a_failed_sync_keeps_the_last_good_answer_and_records_the_error(self) -> None:
        source = _Failing()
        inventory = Inventory(self.data, [source])
        inventory.sync()
        first = inventory.view()[0]
        self.assertIsNone(first["error"])
        self.assertEqual([repo["name"] for repo in first["repositories"]], ["web-app"])
        source.fail = True
        inventory.sync()
        second = inventory.view()[0]
        self.assertIn("HTTP 503", second["error"])
        self.assertEqual([repo["name"] for repo in second["repositories"]], ["web-app"])
        self.assertEqual(second["syncedAt"], first["syncedAt"])
        if os.name != "nt":
            self.assertEqual((self.data / "inventory" / "azure-devops.json").stat().st_mode & 0o777, 0o600)


class RepositoriesEndpointTests(TestCase):
    def setUp(self) -> None:
        name = self.id().split(".")[-1]
        base = ROOT / "build" / "tests" / "repositories" / name
        shutil.rmtree(base, ignore_errors=True)
        self.scans = base / "scans"
        self.data = base / "data"
        for folder, project, branch, failed in (
            ("20261020T000000Z-web-main", "web-app", "main", False),
            ("20261022T000000Z-web-main", "web-app", "main", True),
            ("20261022T000000Z-laptop", "my-laptop-checkout", "main", False),
        ):
            directory = self.scans / folder
            directory.mkdir(parents=True)
            lines = [
                "engine: 13.0.0",
                "snapshot: 2026-10-21T05:00:00Z",
                "checksum: sha256:" + "0" * 64,
                f"project: {project}",
                f"branch: {branch}",
                "score-policy: prefer-newest",
                "threshold: 7",
            ]
            if failed:
                lines.append("prefer-newest failed the build on CVE-2026-1 cvss 3.1 score 9.8 source NVD")
            (directory / "checkstead.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.source = _Failing()
        self.server = bind_server(self.scans, "127.0.0.1", 0, self.data, sources=[self.source])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        # Cleanups run last-in first: stop serving before closing the socket.
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        host, port = self.server.server_address[:2]
        self.base = f"http://{host}:{port}"
        self.admin = self._session("admin@example.com")

    def _session(self, login: str, role: str | None = None) -> str:
        store = AccountStore(self.data)
        token, _user = store.sign_in(Identity("entra", login, login, login), role)
        return token

    def request(self, path: str, method: str = "GET", cookie: str | None = None):
        headers = {"Cookie": f"checkstead_session={cookie}"} if cookie else {}
        data = b"{}" if method == "POST" else None
        if data:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_branches_carry_their_newest_scan_and_local_scans_stay_out(self) -> None:
        self.server.inventory.sync()
        status, payload = self.request("/api/repositories", cookie=self.admin)
        self.assertEqual(status, 200, payload)
        source = payload["sources"][0]
        self.assertEqual(source["label"], "Azure DevOps: acme")
        repo = source["repositories"][0]
        self.assertEqual(repo["name"], "web-app")
        self.assertEqual(repo["defaultScan"]["id"], "20261022T000000Z-web-main")
        self.assertEqual(repo["defaultScan"]["findings"], 0)
        self.assertFalse(repo["defaultScan"]["failed"])
        self.assertNotIn("my-laptop-checkout", json.dumps(payload))

    def test_the_branch_status_applies_the_scans_own_policy(self) -> None:
        policy = {"threshold": "7", "failOnKev": "false", "failUnscored": "false"}
        self.assertTrue(_policy_fails({"policy": policy, "findings": [{"score": "9.8"}]}))
        self.assertFalse(_policy_fails({"policy": policy, "findings": [{"score": "6.1"}, {"score": None}]}))
        self.assertTrue(_policy_fails({"policy": {**policy, "failOnKev": "true"}, "findings": [{"score": "4.0", "kev": True}]}))
        self.assertTrue(_policy_fails({"policy": {**policy, "failUnscored": "true"}, "findings": [{"score": None}]}))
        # No threshold means a score never fails the build.
        self.assertFalse(_policy_fails({"policy": {}, "findings": [{"score": "10.0"}]}))

    def test_reading_needs_a_session_and_syncing_needs_an_administrator(self) -> None:
        self.assertEqual(self.request("/api/repositories")[0], 401)
        member = self._session("member@example.com", "user")
        self.assertEqual(self.request("/api/repositories", cookie=member)[0], 200)
        self.assertEqual(self.request("/api/repositories/sync", "POST", member)[0], 403)
        status, payload = self.request("/api/repositories/sync", "POST", self.admin)
        self.assertEqual(status, 202, payload)
        self.assertTrue(payload["syncing"])

    def test_runs_are_listed_per_source(self) -> None:
        self.server.inventory.sync()
        status, payload = self.request("/api/runs", cookie=self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(payload["sources"][0]["kind"], "azure-devops")
        self.assertEqual(payload["sources"][0]["runs"], [])


class EntraGroupAccessTests(TestCase):
    def setUp(self) -> None:
        self.data = ROOT / "build" / "tests" / "groups" / self.id().split(".")[-1]
        shutil.rmtree(self.data, ignore_errors=True)
        self.store = AccountStore(self.data)
        self.store.sign_in(Identity("entra", "owner", "owner@example.com", "Owner"))
        patcher = mock.patch.dict(
            os.environ,
            {"CHECKSTEAD_ENTRA_ADMIN_GROUPS": ADMINS, "CHECKSTEAD_ENTRA_ALLOWED_GROUPS": MEMBERS.upper()},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _person(self, login: str, *groups: str) -> Identity:
        return Identity("entra", login, f"{login}@example.com", login, groups=frozenset(groups))

    def test_a_member_group_admits_without_an_administrator(self) -> None:
        person = self._person("ada", MEMBERS)
        _token, user = self.store.sign_in(person, entra_group_role(person))
        self.assertEqual(user["role"], "user")

    def test_the_admin_group_makes_and_promotes_administrators(self) -> None:
        person = self._person("grace", MEMBERS)
        self.store.sign_in(person, entra_group_role(person))
        promoted = self._person("grace", MEMBERS, ADMINS)
        _token, user = self.store.sign_in(promoted, entra_group_role(promoted))
        self.assertEqual(user["role"], "admin")
        # Leaving the admin group does not demote: that could lock out the last administrator.
        _token, user = self.store.sign_in(person, entra_group_role(person))
        self.assertEqual(user["role"], "admin")

    def test_no_group_still_needs_an_administrator(self) -> None:
        person = self._person("eve", "33333333-cccc-4ccc-8ccc-333333333333")
        self.assertIsNone(entra_group_role(person))
        with self.assertRaises(AccountError) as caught:
            self.store.sign_in(person, entra_group_role(person))
        self.assertEqual(caught.exception.status, 403)

    def test_groups_never_admit_another_provider(self) -> None:
        github = Identity("github", "1", "ada", "Ada", groups=frozenset({MEMBERS}))
        self.assertIsNone(entra_group_role(github))

    def test_id_token_groups_and_the_overage_link(self) -> None:
        groups, overage = _entra_groups({"groups": [MEMBERS.upper(), "not-a-guid", 7]})
        self.assertEqual(groups, frozenset({MEMBERS}))
        self.assertFalse(overage)
        groups, overage = _entra_groups({"_claim_names": {"groups": "src1"}, "_claim_sources": {}})
        self.assertEqual(groups, frozenset())
        self.assertTrue(overage)

    def test_a_malformed_group_setting_is_refused(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_ENTRA_ALLOWED_GROUPS": "engineers"}):
            person = self._person("ada", MEMBERS)
            with self.assertRaises(AuthError) as caught:
                entra_group_role(person)
        self.assertIn("group object ids", str(caught.exception))
