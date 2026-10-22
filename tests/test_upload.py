"""Pipelines send their reports; the server groups them by the repository they came from.

The model is SonarQube's: a pipeline step sends the analysis with a server
token, and the server learns the repository and branch from it. No Git host
is contacted here.
"""

from __future__ import annotations

import http.client
import io
import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import TestCase, mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from checkstead.accounts import AccountError, AccountStore  # noqa: E402
from checkstead.errors import ChecksteadError  # noqa: E402
from checkstead.identity import Identity  # noqa: E402
from checkstead.origin import build_link, clean_url, parse_repository_url  # noqa: E402
from checkstead.ui import bind_server  # noqa: E402
from checkstead.upload import report_zip, send_report  # noqa: E402
from test_phase1 import FixtureServer, manifest_for, run_cli, write_zip  # noqa: E402

REPO_URL = "https://dev.azure.com/Ascertra/Proarc-Products/_git/proarc.cloudoperations"
BUILD_URL = "https://dev.azure.com/Ascertra/b6b767a3-4823-41ab-a6b5-09c215ec3c30/_build/results?buildId=130078"


def _report(folder: Path, branch: str, repository_url: str | None = REPO_URL, project: str = "proarc.cloudoperations") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    lines = [
        "engine: 13.0.0",
        "snapshot: 2026-10-21T05:00:00Z",
        "checksum: sha256:" + "0" * 64,
        f"project: {project}",
        f"revision: {'a' * 40}",
        f"branch: {branch}",
        "score-policy: prefer-newest",
        "threshold: 7",
    ]
    if repository_url:
        lines += [f"repository-url: {repository_url}", f"build-url: {BUILD_URL}"]
    (folder / "checkstead.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (folder / "checkstead.sarif").write_text("{}", encoding="utf-8")
    return folder


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class OriginTests(TestCase):
    def test_azure_devops_urls_name_organization_project_and_repository(self) -> None:
        origin = parse_repository_url("https://Ascertra@dev.azure.com/Ascertra/Proarc-Products/_git/proarc.cloudoperations")
        self.assertEqual(
            (origin.provider, origin.organization, origin.project, origin.repository),
            ("azure-devops", "Ascertra", "Proarc-Products", "proarc.cloudoperations"),
        )
        # The organization in userinfo is dropped, never stored.
        self.assertEqual(origin.url, REPO_URL)
        old = parse_repository_url("https://ascertra.visualstudio.com/DefaultCollection/Proarc-Products/_git/web")
        self.assertEqual((old.organization, old.project, old.repository), ("ascertra", "Proarc-Products", "web"))
        same = parse_repository_url("https://ascertra.visualstudio.com/_git/Tools")
        self.assertEqual((same.project, same.repository), ("Tools", "Tools"))

    def test_github_and_other_hosts(self) -> None:
        github = parse_repository_url("https://github.com/chethankumblekar/dependency-check-db-cache.git")
        self.assertEqual((github.provider, github.organization, github.repository), ("github", "chethankumblekar", "dependency-check-db-cache"))
        self.assertEqual(github.url, "https://github.com/chethankumblekar/dependency-check-db-cache")
        other = parse_repository_url("https://git.example.com/team/sub/app.git")
        self.assertEqual((other.provider, other.organization, other.project, other.repository), ("git", "git.example.com", "team/sub", "app"))

    def test_only_plain_https_urls_are_kept(self) -> None:
        self.assertIsNone(clean_url("http://dev.azure.com/a/b/_git/c"))
        self.assertIsNone(clean_url("file:///etc/passwd"))
        self.assertIsNone(clean_url("https://dev.azure.com/a b/_git/c"))
        self.assertIsNone(clean_url("https://dev.azure.com/a\n/b"))
        self.assertEqual(clean_url("https://user:secret@dev.azure.com/a/b/_git/c?x=1#y"), "https://dev.azure.com/a/b/_git/c")
        self.assertEqual(build_link(BUILD_URL), BUILD_URL)
        self.assertIsNone(parse_repository_url("https://dev.azure.com/a/b/c"))


class UploadTokenTests(TestCase):
    def setUp(self) -> None:
        self.data = ROOT / "build" / "tests" / "upload-tokens" / self.id().split(".")[-1]
        shutil.rmtree(self.data, ignore_errors=True)
        self.store = AccountStore(self.data)

    def test_a_token_is_shown_once_kept_as_a_hash_and_revocable(self) -> None:
        token, record = self.store.create_upload_token("  proarc  pipelines ", 1)
        self.assertTrue(token.startswith("cks_"))
        self.assertEqual(record["name"], "proarc pipelines")
        self.assertNotIn(token, json.dumps(self.store.list_upload_tokens()))
        self.assertNotIn(token.encode(), (self.data / "accounts.sqlite").read_bytes())
        self.assertIsNone(record["lastUsedAt"])
        used = self.store.check_upload_token(token)
        self.assertEqual(used["id"], record["id"])
        self.assertIsNotNone(used["lastUsedAt"])
        self.assertIsNone(self.store.check_upload_token(token + "x"))
        self.assertIsNone(self.store.check_upload_token("ghp_" + token[4:]))
        self.store.revoke_upload_token(record["id"])
        self.assertIsNone(self.store.check_upload_token(token))
        with self.assertRaises(AccountError):
            self.store.revoke_upload_token(record["id"])

    def test_a_token_needs_a_name(self) -> None:
        with self.assertRaises(AccountError):
            self.store.create_upload_token("   ", 1)


class UploadEndpointTests(TestCase):
    def setUp(self) -> None:
        base = ROOT / "build" / "tests" / "upload" / self.id().split(".")[-1]
        shutil.rmtree(base, ignore_errors=True)
        self.base_dir = base
        self.scans = base / "scans"
        self.data = base / "data"
        _report(self.scans / "20261020T000000Z-laptop", "main", repository_url=None, project="my-checkout")
        self.server = bind_server(self.scans, "127.0.0.1", 0, self.data, sources=[])
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.host, self.port = self.server.server_address[:2]
        self.url = f"http://{self.host}:{self.port}"
        store = AccountStore(self.data)
        self.admin, _user = store.sign_in(Identity("entra", "admin", "admin@example.com", "Admin"))
        self.member, _user = store.sign_in(Identity("entra", "member", "member@example.com", "Member"), "user")
        self.token, self.token_record = store.create_upload_token("pipelines", 1)

    def _post(self, body: bytes, token: str | None, headers: dict | None = None):
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        all_headers = {"Content-Type": "application/zip", "Content-Length": str(len(body)), **(headers or {})}
        if token:
            all_headers["Authorization"] = f"Bearer {token}"
        connection.request("POST", "/api/scans/upload", body=body, headers=all_headers)
        response = connection.getresponse()
        payload = json.loads(response.read() or b"{}")
        closed = response.getheader("Connection", "").lower() == "close"
        connection.close()
        return response.status, payload, closed

    def _get(self, path: str, cookie: str | None = None, method: str = "GET", body: dict | None = None):
        headers = {"Cookie": f"checkstead_session={cookie}"} if cookie else {}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_a_pipeline_report_lands_under_its_organization_project_and_repository(self) -> None:
        body = report_zip(_report(self.base_dir / "out-main", "main"))
        status, payload, _closed = self._post(body, self.token)
        self.assertEqual(status, 201, payload)
        self.assertTrue((self.scans / payload["id"] / "checkstead.txt").is_file())
        self.assertTrue((self.scans / payload["id"] / "checkstead.sarif").is_file())
        status, feature, _closed = self._post(report_zip(_report(self.base_dir / "out-feature", "feature/add-axios")), self.token)
        self.assertEqual(status, 201, feature)

        status, repos = self._get("/api/repositories", self.member)
        self.assertEqual(status, 200, repos)
        [org] = [source for source in repos["sources"] if source.get("reported")]
        self.assertEqual(org["label"], "Azure DevOps: Ascertra")
        [repo] = org["repositories"]
        self.assertEqual((repo["project"], repo["name"], repo["url"]), ("Proarc-Products", "proarc.cloudoperations", REPO_URL))
        self.assertEqual(repo["defaultBranch"], "main")
        self.assertEqual(repo["defaultScan"]["id"], payload["id"])
        self.assertEqual([branch["name"] for branch in repo["branches"]], ["feature/add-axios", "main"])
        self.assertEqual(repo["branches"][1]["scan"]["buildUrl"], BUILD_URL)
        # A scan of a checkout has no repository URL and is not a repository here.
        self.assertNotIn("my-checkout", json.dumps(repos))
        status, history = self._get("/api/history/summary", self.member)
        self.assertIn("my-checkout", json.dumps(history))

    def test_no_token_or_a_wrong_one_is_refused_before_the_body_is_read(self) -> None:
        body = report_zip(_report(self.base_dir / "out", "main"))
        for token in (None, "cks_wrong", "ghp_" + self.token[4:]):
            with self.subTest(token=token):
                status, payload, closed = self._post(body, token)
                self.assertEqual(status, 401)
                self.assertIn("upload token", payload["error"])
                self.assertTrue(closed)
        self.assertEqual(len([path for path in self.scans.iterdir() if path.is_dir()]), 1)

    def test_anything_but_report_files_is_refused(self) -> None:
        good = (_report(self.base_dir / "out", "main") / "checkstead.txt").read_bytes()
        cases = {
            "not a zip": b"plain text",
            "path traversal": _zip({"../checkstead.txt": good}),
            "nested": _zip({"sub/checkstead.txt": good}),
            "unknown file": _zip({"checkstead.txt": good, "run.sh": b"echo hi"}),
            "no report": _zip({"checkstead.sarif": b"{}"}),
            "not a checkstead report": _zip({"checkstead.txt": b"hello: world\n"}),
        }
        for label, body in cases.items():
            with self.subTest(label=label):
                status, payload, _closed = self._post(body, self.token)
                self.assertEqual(status, 400, payload)
        self.assertEqual(len([path for path in self.scans.iterdir() if path.is_dir()]), 1)

    def test_an_upload_over_the_limit_is_refused_without_reading_it(self) -> None:
        with mock.patch.dict(os.environ, {"CHECKSTEAD_MAX_UPLOAD_MB": "1"}):
            connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
            connection.putrequest("POST", "/api/scans/upload")
            connection.putheader("Authorization", f"Bearer {self.token}")
            connection.putheader("Content-Type", "application/zip")
            connection.putheader("Content-Length", str(5 * 1024 * 1024))
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 413)
            connection.close()

    def test_administrators_manage_upload_tokens_and_members_cannot(self) -> None:
        self.assertEqual(self._get("/api/admin/upload-tokens", self.member)[0], 403)
        self.assertEqual(self._get("/api/admin/upload-tokens", self.member, "POST", {"name": "x"})[0], 403)
        status, created = self._get("/api/admin/upload-tokens", self.admin, "POST", {"name": "ci"})
        self.assertEqual(status, 201, created)
        self.assertTrue(created["token"].startswith("cks_"))
        status, listing = self._get("/api/admin/upload-tokens", self.admin)
        self.assertEqual([item["name"] for item in listing["uploadTokens"]], ["pipelines", "ci"])
        self.assertNotIn(created["token"], json.dumps(listing))
        new_id = created["uploadToken"]["id"]
        self.assertEqual(self._get(f"/api/admin/upload-tokens/{new_id}", self.member, "DELETE")[0], 403)
        self.assertEqual(self._get(f"/api/admin/upload-tokens/{new_id}", self.admin, "DELETE")[0], 200)
        status, _payload, _closed = self._post(report_zip(_report(self.base_dir / "out", "main")), created["token"])
        self.assertEqual(status, 401)

    def test_the_upload_command_sends_the_folder_and_reads_the_token_from_the_environment(self) -> None:
        folder = _report(self.base_dir / "cli-out", "develop")
        result = send_report(self.url, folder, self.token)
        self.assertTrue(result["url"].startswith(self.url + "/#/scans/"))
        self.assertTrue((self.scans / result["id"] / "checkstead.txt").is_file())
        with self.assertRaises(ChecksteadError) as caught:
            send_report(self.url, folder, "")
        self.assertIn("CHECKSTEAD_UPLOAD_TOKEN", str(caught.exception))
        with self.assertRaises(ChecksteadError) as caught:
            send_report(self.url, folder, "cks_wrong")
        self.assertIn("HTTP 401", str(caught.exception))
        with self.assertRaises(ChecksteadError):
            send_report("http://checkstead.example", folder, self.token)
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "CHECKSTEAD_UPLOAD_TOKEN": self.token}
        completed = run_cli(["upload", "--server", self.url, "--report", str(folder)], env, ROOT)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("uploaded:", completed.stdout)
        self.assertNotIn(self.token, completed.stdout + completed.stderr)


class PipelineExampleTests(TestCase):
    def test_both_azure_devops_examples_record_the_origin_and_send_the_report(self) -> None:
        entry = (ROOT / "scripts" / "docker-entrypoint.sh").read_text(encoding="utf-8")
        self.assertIn('"${1:-}" == "upload"', entry)
        for name in ("pr-ci.yml", "pull-request.yml"):
            with self.subTest(example=name):
                text = (ROOT / "integrations" / "azure-devops" / name).read_text(encoding="utf-8")
                self.assertIn('--repository-url "$BUILD_REPOSITORY_URI"', text)
                self.assertIn("--build-url", text)
                self.assertIn('upload --server "$CHECKSTEAD_SERVER" --report /out', text)
                # The secret reaches only the upload step, mapped by name.
                self.assertIn("CHECKSTEAD_UPLOAD_TOKEN: $(CHECKSTEAD_UPLOAD_TOKEN)", text)
                self.assertEqual(text.count("$(CHECKSTEAD_UPLOAD_TOKEN)"), 1)
                self.assertNotIn("cks_", text)


class ScanOriginHeaderTests(TestCase):
    def test_the_report_records_the_repository_and_build_without_credentials(self) -> None:
        root = ROOT / "build" / "tests" / "scan-origin"
        shutil.rmtree(root, ignore_errors=True)
        (root / "src").mkdir(parents=True)
        blob = root / "db.zip"
        write_zip(blob, "origin")
        server = FixtureServer()
        self.addCleanup(server.close)
        server.manifest = manifest_for(blob, "2026-10-06T01:02:03Z")
        server.zip_bytes = blob.read_bytes()
        config = root / "checkstead.yml"
        config.write_text(f"snapshot: {server.manifest_url}\nscorePolicy: prefer-newest\nthreshold:\nfailOnKev: false\nfailUnscored: false\nprivateSuppressions:\n", encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "CHECKSTEAD_TODAY": "2026-10-06"}
        completed = run_cli(
            [
                "scan", "--dry-run", "--scan", str(root / "src"), "--out", str(root / "out"), "--cache", str(root / "cache"),
                "--config", str(config), "--branch", "main",
                "--repository-url", "https://Ascertra@dev.azure.com/Ascertra/Proarc-Products/_git/proarc.cloudoperations",
                "--build-url", BUILD_URL,
            ],
            env,
            root,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = (root / "out" / "checkstead.txt").read_text(encoding="utf-8")
        self.assertIn(f"repository-url: {REPO_URL}\n", report)
        self.assertIn(f"build-url: {BUILD_URL}\n", report)
        self.assertNotIn("Ascertra@", report)
