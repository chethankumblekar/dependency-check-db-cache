"""An organization owner installs a GitHub App and scans from the local server."""

from __future__ import annotations

import base64
import html
import json
import os
import re
import stat
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.config import DEFAULT_SNAPSHOT_URL  # noqa: E402
from checkstead.errors import ChecksteadError, RefusedHost  # noqa: E402
from checkstead.history import load_history  # noqa: E402
from checkstead.github_app import (  # noqa: E402
    ActionsPermissionRequired,
    accept_installation,
    app_jwt,
    begin_manifest,
    build_manifest,
    github_request,
    list_workflow_runs,
    localhost_client,
    manifest_target,
    rerun_workflow,
    scan_installed_repositories,
)
from checkstead.identity import github_api_base, github_web_base  # noqa: E402
from checkstead.ui import bind_server  # noqa: E402

LOCAL_COMMAND = (
    "curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/"
    "main/scripts/local.sh | bash"
)


def _pem() -> str:
    completed = subprocess.run(
        ["openssl", "genrsa", "2048"],
        check=True,
        capture_output=True,
    )
    return completed.stdout.decode("utf-8")


@contextmanager
def github_env(api: str | None = None, oauth: str | None = None):
    names = ("CHECKSTEAD_GITHUB_API", "CHECKSTEAD_GITHUB_OAUTH")
    saved = {name: os.environ.get(name) for name in names}
    for name in names:
        os.environ.pop(name, None)
    if api:
        os.environ["CHECKSTEAD_GITHUB_API"] = api
    if oauth:
        os.environ["CHECKSTEAD_GITHUB_OAUTH"] = oauth
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


class GitHubAppTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pem = _pem()

    def _work(self, name: str) -> Path:
        path = ROOT / "build" / "tests" / "github" / name
        if path.exists():
            subprocess.run(["rm", "-rf", str(path)], check=True)
        path.mkdir(parents=True)
        return path

    def _store_app(self, data: Path, pem: str | None = None) -> None:
        directory = data / "github-app"
        directory.mkdir(parents=True)
        (directory / "app.json").write_text(
            json.dumps({"id": 15, "slug": "checkstead", "organization": "acme"}),
            encoding="utf-8",
        )
        key = directory / "private-key.pem"
        key.write_text(pem if pem is not None else self.pem, encoding="utf-8")
        os.chmod(key, 0o600)

    def test_api_default_is_github_com_and_enterprise_server_is_configurable(self) -> None:
        with github_env():
            self.assertEqual(github_api_base(), "https://api.github.com")
            self.assertEqual(github_web_base(), "https://github.com")
            target = manifest_target("acme", "state")
        self.assertEqual(
            target,
            "https://github.com/organizations/acme/settings/apps/new?state=state",
        )
        with github_env(api="https://github.example.com/api/v3"):
            self.assertEqual(github_web_base(), "https://github.example.com")
            enterprise = manifest_target("acme", "state")
            manifest = build_manifest("http://127.0.0.1:8765")
        self.assertEqual(
            enterprise,
            "https://github.example.com/organizations/acme/settings/apps/new?state=state",
        )
        self.assertNotIn("https://github.com/", enterprise)
        self.assertEqual(
            manifest["default_permissions"],
            {"actions": "write", "contents": "read", "metadata": "read"},
        )
        with github_env(api="https://github.example.com/api/v3", oauth="https://override.example"):
            self.assertEqual(github_web_base(), "https://override.example")

    def test_a_user_installation_is_stored_for_that_user(self) -> None:
        data = self._work("install")
        self._store_app(data, pem="not-a-key\n")
        with self.assertRaises(ChecksteadError) as refused:
            accept_installation(data, {"id": 9, "account": {"login": "octocat", "type": "User"}})
        self.assertIn("organization", str(refused.exception))
        self.assertNotIn("PRIVATE KEY", str(refused.exception))
        self.assertFalse((data / "github-app" / "installation.json").exists())
        with self.assertRaises(ChecksteadError):
            accept_installation(
                data,
                {"id": 9, "account": {"login": "other-org", "type": "Organization"}},
            )
        self.assertFalse((data / "github-app" / "installation.json").exists())
        stored = accept_installation(
            data,
            {"id": 9, "account": {"login": "acme", "type": "Organization"}},
        )
        self.assertEqual(stored, {"id": 9, "organization": "acme"})
        saved = json.loads((data / "github-app" / "installation.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["accountType"], "Organization")
        (data / "github-app" / "app.json").write_text(
            json.dumps({"id": 15, "slug": "checkstead", "organization": "octocat", "accountType": "User"}),
            encoding="utf-8",
        )
        personal = accept_installation(
            data,
            {"id": 11, "account": {"login": "octocat", "type": "User"}},
        )
        self.assertEqual(personal, {"id": 11, "organization": "octocat"})
        saved = json.loads((data / "github-app" / "installation.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["accountType"], "User")

    def test_a_personal_account_creates_the_app_and_scans_that_users_repositories(self) -> None:
        root = self._work("personal")
        data = root / "data"
        calls: list[str] = []

        def transport(method: str, url: str, headers: dict, body):
            calls.append(url)
            self.assertNotIn("services.nvd.nist.gov", url)
            if url.endswith("/users/octocat"):
                return 200, json.dumps({"login": "octocat", "type": "User"}).encode()
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_user"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps(
                    {"repositories": [{"full_name": "octocat/hello", "default_branch": "main"}]}
                ).encode()
            raise AssertionError(url)

        page = begin_manifest(data, "octocat", "http://127.0.0.1:8765", "state-user", transport)
        self.assertIn("https://github.com/settings/apps/new?state=state-user", page)
        self.assertNotIn("/organizations/octocat/", page)
        self.assertEqual(manifest_target("octocat", "state-user", "User"), "https://github.com/settings/apps/new?state=state-user")
        directory = data / "github-app"
        (directory / "app.json").write_text(
            json.dumps({"id": 15, "slug": "checkstead", "organization": "octocat", "accountType": "User"}),
            encoding="utf-8",
        )
        (directory / "private-key.pem").write_text(self.pem, encoding="utf-8")
        stored = accept_installation(
            data,
            {"id": 77, "account": {"login": "octocat", "type": "User"}},
        )
        self.assertEqual(stored["organization"], "octocat")
        seen: list[dict] = []

        def fake_scan(paths, **kwargs):
            seen.append(kwargs)
            out = kwargs["out_dir"]
            out.mkdir(parents=True, exist_ok=True)
            (out / "checkstead.txt").write_text(
                f"branch: {kwargs.get('branch') or ''}\nscore-policy: {kwargs['score_policy']}\n",
                encoding="utf-8",
            )

        def fetch_zip(url: str, headers: dict, dest: Path) -> None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest, "w") as archive:
                archive.writestr("octocat-hello/README", "hi\n")

        with github_env():
            results = scan_installed_repositories(
                data,
                root / "scans",
                root,
                transport,
                fake_scan,
                fetch_zip,
            )
        self.assertEqual(results[0]["repository"], "octocat/hello")
        self.assertNotIn("error", results[0])
        self.assertEqual(seen[0]["branch"], "main")
        self.assertEqual(seen[0]["private_suppressions"], "")
        for url in calls:
            self.assertNotIn("services.nvd.nist.gov", url)

    def test_jwt_signs_with_openssl_and_the_nvd_is_refused(self) -> None:
        data = self._work("jwt")
        key = data / "private-key.pem"
        key.write_text(self.pem, encoding="utf-8")
        token = app_jwt("15", key, now=1_700_000_000)
        header, payload, signature = token.split(".")
        padded = payload + "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        self.assertEqual(claims["iss"], "15")
        self.assertEqual(claims["iat"], 1_700_000_000 - 60)
        self.assertEqual(claims["exp"], 1_700_000_000 + 540)
        self.assertTrue(header.startswith("eyJ"))
        signing = f"{header}.{payload}".encode("ascii")
        sig = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        sig_path = data / "sig"
        sig_path.write_bytes(sig)
        pub = data / "public.pem"
        subprocess.run(
            ["openssl", "rsa", "-in", str(key), "-pubout", "-out", str(pub)],
            check=True,
            capture_output=True,
        )
        verified = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig_path)],
            input=signing,
            capture_output=True,
            check=False,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode())
        called = []

        def transport(*_args):
            called.append(True)
            return 200, b"{}"

        with self.assertRaises(RefusedHost):
            github_request(
                "GET",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                {},
                None,
                transport,
            )
        self.assertEqual(called, [])

    def test_scan_uses_the_score_policy_and_leaves_suppressions_optional(self) -> None:
        root = self._work("scan")
        data = root / "data"
        cwd = root / "project"
        scans = root / "scans"
        cwd.mkdir()
        (cwd / "checkstead.yml").write_text(
            "scorePolicy: highest\nthreshold: 7\nfailOnKev: true\nfailUnscored: false\n",
            encoding="utf-8",
        )
        self._store_app(data)
        (data / "github-app" / "installation.json").write_text(
            json.dumps({"id": 42, "organization": "acme", "accountType": "Organization"}),
            encoding="utf-8",
        )
        calls: list[str] = []

        def transport(method: str, url: str, headers: dict, body):
            calls.append(url)
            self.assertNotIn("services.nvd.nist.gov", url)
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_test"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps({"repositories": [{"full_name": "acme/widget"}]}).encode()
            raise AssertionError(url)

        fetched: list[str] = []

        def fetch_zip(url: str, headers: dict, dest: Path) -> None:
            fetched.append(url)
            self.assertNotIn("ghs_test", url)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest, "w") as archive:
                archive.writestr("acme-widget-sha/README", "hello\n")

        seen: list[dict] = []

        def fake_scan(paths, **kwargs):
            seen.append(kwargs)
            self.assertTrue(paths[0].is_dir())
            out = kwargs["out_dir"]
            out.mkdir(parents=True, exist_ok=True)
            (out / "checkstead.txt").write_text(
                f"score-policy: {kwargs['score_policy']}\n",
                encoding="utf-8",
            )

        with github_env(api="https://github.example.com/api/v3"):
            results = scan_installed_repositories(
                data,
                scans,
                cwd,
                transport,
                fake_scan,
                fetch_zip,
            )
        self.assertEqual(results[0]["repository"], "acme/widget")
        self.assertEqual(results[0]["scorePolicy"], "highest")
        self.assertEqual(results[0]["privateSuppressions"], "")
        self.assertEqual(results[0]["threshold"], 7)
        self.assertNotIn("error", results[0])
        self.assertEqual(seen[0]["score_policy"], "highest")
        self.assertEqual(seen[0]["private_suppressions"], "")
        self.assertEqual(seen[0]["config_snapshot_url"], DEFAULT_SNAPSHOT_URL)
        self.assertTrue(seen[0]["fail_on_kev"])
        self.assertFalse(seen[0]["fail_unscored"])
        self.assertEqual(
            fetched,
            ["https://github.example.com/api/v3/repos/acme/widget/zipball"],
        )
        self.assertTrue(any(url.startswith("https://github.example.com/api/v3/") for url in calls))
        for url in calls + fetched:
            self.assertNotIn("services.nvd.nist.gov", url)
        self.assertNotIn("nvdApiKey", str(seen[0]))
        self.assertNotIn("services.nvd.nist.gov", str(seen[0]))
        self.assertNotIn("ghs_test", Path(results[0]["report"]).read_text(encoding="utf-8"))
        self.assertIn("score-policy: highest", Path(results[0]["report"]).read_text(encoding="utf-8"))

        (cwd / "checkstead.yml").write_text(
            "scorePolicy: prefer-newest\nprivateSuppressions: missing.xml\n",
            encoding="utf-8",
        )
        seen.clear()
        with github_env(api="https://github.example.com/api/v3"):
            forwarded = scan_installed_repositories(
                data,
                scans,
                cwd,
                transport,
                fake_scan,
                fetch_zip,
            )
        self.assertEqual(forwarded[0]["privateSuppressions"], "missing.xml")
        self.assertEqual(seen[0]["private_suppressions"], "missing.xml")
        self.assertNotIn("error", forwarded[0])

    def test_local_command_starts_the_server_after_setup(self) -> None:
        script = (ROOT / "scripts" / "local.sh").read_text(encoding="utf-8")
        self.assertIn("setup.sh", script)
        self.assertIn("CHECKSTEAD_LOCAL=1", script)
        self.assertIn("import checkstead.github_app", script)
        self.assertIn(
            '"$HOME/checkstead/bin/checkstead" ui --host 127.0.0.1 --port 8765',
            script,
        )
        self.assertNotIn("services.nvd.nist.gov", script)
        self.assertNotIn("NVD_API_KEY", script)
        subprocess.run(["bash", "-n", str(ROOT / "scripts" / "local.sh")], check=True)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertLess(readme.index(LOCAL_COMMAND), readme.index("## Architecture"))
        self.assertIn(
            "irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex",
            readme,
        )
        self.assertIn("prefer-newest", readme)
        self.assertIn("privateSuppressions", readme)
        self.assertIn("click **Install**", readme)
        self.assertNotIn("Create a token", readme)
        self.assertNotIn("read:user", readme)
        self.assertNotIn("paste", readme.lower())
        self.assertTrue(localhost_client("127.0.0.1"))
        self.assertTrue(localhost_client("::1"))
        self.assertFalse(localhost_client("10.0.0.8"))

    def test_owner_can_install_the_app_and_scan_from_the_local_server(self) -> None:
        root = self._work("http")
        data = root / "data"
        scans = root / "scans"
        cwd = root / "project"
        scans.mkdir()
        cwd.mkdir()
        (cwd / "checkstead.yml").write_text(
            "scorePolicy: highest\nfailOnKev: false\nfailUnscored: false\n",
            encoding="utf-8",
        )
        installation = {"id": 42, "account": {"login": "octocat", "type": "User"}}
        calls: list[str] = []

        def transport(method: str, url: str, headers: dict, body):
            calls.append(url)
            self.assertNotIn("services.nvd.nist.gov", url)
            if url.endswith("/users/acme"):
                return 200, json.dumps({"login": "acme", "type": "Organization"}).encode()
            if url.endswith("/conversions"):
                return 201, json.dumps(
                    {
                        "id": 15,
                        "slug": "checkstead",
                        "pem": self.pem,
                        "client_id": "Iv1.test",
                        "client_secret": "secret-value",
                        "webhook_secret": "hook-secret",
                    }
                ).encode()
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_test"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps({"repositories": [{"full_name": "acme/widget"}]}).encode()
            if "/app/installations/" in url:
                return 200, json.dumps(installation).encode()
            raise AssertionError(url)

        def fetch_zip(url: str, headers: dict, dest: Path) -> None:
            calls.append(url)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest, "w") as archive:
                archive.writestr("acme-widget-sha/README", "hello\n")

        def fake_scan(paths, **kwargs):
            out = kwargs["out_dir"]
            out.mkdir(parents=True, exist_ok=True)
            (out / "checkstead.txt").write_text(
                f"score-policy: {kwargs['score_policy']}\n"
                f"private-suppressions: {kwargs['private_suppressions'] or 'none'}\n",
                encoding="utf-8",
            )

        server = bind_server(
            scans,
            "127.0.0.1",
            0,
            data,
            github_transport=transport,
            github_scan=fake_scan,
            github_fetch_zip=fetch_zip,
            config_cwd=cwd,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        base = f"http://{host}:{port}"

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)

        opener = urllib.request.build_opener(_NoRedirect)

        def request(path: str, method: str = "GET", data_bytes: bytes | None = None, headers: dict | None = None):
            req = urllib.request.Request(base + path, data=data_bytes, headers=headers or {}, method=method)
            try:
                with opener.open(req) as response:
                    return response.status, response.read(), response.headers
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read(), exc.headers

        with github_env(api="https://github.example.com/api/v3"):
            status, body, _headers = request("/api/github")
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertEqual(payload["api"], "https://github.example.com/api/v3")
            self.assertEqual(payload["web"], "https://github.example.com")
            self.assertIsNone(payload["app"])
            status, page, _headers = request("/github")
            self.assertEqual(status, 200)
            self.assertIn(b"GitHub login", page)
            self.assertIn(b"Personal account", page)
            self.assertIn(b'name="account" value="user"', page)
            self.assertIn(b"Organization", page)
            self.assertIn(b"For a personal account, type the user login.", page)
            self.assertNotIn(b'name="token"', page)
            self.assertNotIn(b"personal access", page.lower())
            self.assertIn(b"There is no token field.", page)

            form = urllib.parse.urlencode({"organization": "acme"}).encode()
            status, page, headers = request(
                "/api/github/manifest",
                "POST",
                form,
                {"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200)
            cookie = headers.get("Set-Cookie")
            state = cookie.split(";", 1)[0].split("=", 1)[1]
            action = html.unescape(re.search(br'action="([^"]+)"', page).group(1).decode())
            self.assertTrue(
                action.startswith(
                    "https://github.example.com/organizations/acme/settings/apps/new?state="
                )
            )
            self.assertNotIn("https://github.com/", action)
            self.assertIn("contents", page.decode())
            self.assertIn("metadata", page.decode())
            self.assertIn("actions", page.decode())
            self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(action).query)["state"][0], state)

            status, page, _headers = request(
                "/api/github/manifest/callback?code=demo-code-123&state=nope",
                headers={"Cookie": f"checkstead_github={state}"},
            )
            self.assertEqual(status, 400)

            status, page, headers = request(
                f"/api/github/manifest/callback?code=demo-code-123&state={state}",
                headers={"Cookie": f"checkstead_github={state}"},
            )
            location = headers.get("Location")
            self.assertEqual(status, 302, page.decode(errors="replace"))
            self.assertEqual(location, "https://github.example.com/apps/checkstead/installations/new")
            self.assertNotIn("services.nvd.nist.gov", location)
            self.assertNotIn(b"PRIVATE KEY", page)
            self.assertNotIn(b"secret-value", page)
            self.assertNotIn(b"https://github.com/", page)
            self.assertNotIn("https://github.com/", location)
            key = data / "github-app" / "private-key.pem"
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((data / "github-app" / "credentials.json").stat().st_mode), 0o600)
            self.assertNotIn("secret-value", (data / "github-app" / "app.json").read_text(encoding="utf-8"))
            self.assertNotIn("PRIVATE KEY", (data / "github-app" / "app.json").read_text(encoding="utf-8"))
            status, body, _headers = request("/api/github")
            self.assertNotIn(b"secret-value", body)
            self.assertNotIn(b"PRIVATE KEY", body)
            self.assertIsNone(json.loads(body)["installation"])

            status, page, _headers = request("/api/github/setup?installation_id=42")
            self.assertEqual(status, 400, page.decode())
            self.assertIn(b"organization", page)
            self.assertNotIn(b"PRIVATE KEY", page)
            self.assertFalse((data / "github-app" / "installation.json").exists())

            installation["account"] = {"login": "other-org", "type": "Organization"}
            status, page, _headers = request("/api/github/setup?installation_id=42")
            self.assertEqual(status, 400, page.decode())
            self.assertFalse((data / "github-app" / "installation.json").exists())

            installation["account"] = {"login": "acme", "type": "Organization"}
            status, page, _headers = request("/api/github/setup?installation_id=42")
            self.assertEqual(status, 200, page.decode())
            self.assertIn(b"accepted the installation on acme", page)
            saved = json.loads((data / "github-app" / "installation.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["organization"], "acme")
            self.assertEqual(saved["accountType"], "Organization")

            status, body, _headers = request("/api/github/hook", "POST", b'{"zen":"keep"}')
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body), {"ok": True})

            status, body, _headers = request(
                "/api/github/scan",
                "POST",
                b"{}",
                {"Accept": "application/json", "Content-Type": "application/json"},
            )
            self.assertEqual(status, 200, body.decode())
            scanned = json.loads(body)["scans"][0]
            self.assertEqual(scanned["repository"], "acme/widget")
            self.assertEqual(scanned["scorePolicy"], "highest")
            self.assertEqual(scanned["privateSuppressions"], "")
            self.assertNotIn("error", scanned)
            self.assertNotIn("ghs_test", body.decode())
            self.assertNotIn("PRIVATE KEY", body.decode())
            report = Path(scanned["report"]).read_text(encoding="utf-8")
            self.assertIn("score-policy: highest", report)
            self.assertIn("private-suppressions: none", report)
            for url in calls:
                self.assertNotIn("services.nvd.nist.gov", url)

    def test_labeled_personal_account_scans_into_the_server_directory(self) -> None:
        root = self._work("personal-choice")
        data = root / "data"
        scans = root / "scans"
        cwd = root / "project"
        scans.mkdir()
        cwd.mkdir()
        calls: list[str] = []

        def transport(method: str, url: str, headers: dict, body):
            calls.append(url)
            self.assertNotIn("/users/", url)
            self.assertNotIn("services.nvd.nist.gov", url)
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_user"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps(
                    {
                        "repositories": [
                            {"full_name": "chethankumblekar/demo", "default_branch": "main"}
                        ]
                    }
                ).encode()
            raise AssertionError(url)

        def fetch_zip(url: str, headers: dict, dest: Path) -> None:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(dest, "w") as archive:
                archive.writestr("chethankumblekar-demo-sha/README", "hi\n")

        def fake_scan(paths, **kwargs):
            out = kwargs["out_dir"]
            out.mkdir(parents=True, exist_ok=True)
            (out / "checkstead.txt").write_text(
                "project: chethankumblekar/demo\n"
                f"branch: {kwargs.get('branch') or ''}\n"
                "snapshot: 2026-10-06T01:02:03Z\n",
                encoding="utf-8",
            )

        server = bind_server(
            scans,
            "127.0.0.1",
            0,
            data,
            github_transport=transport,
            github_scan=fake_scan,
            github_fetch_zip=fetch_zip,
            config_cwd=cwd,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        base = f"http://{host}:{port}"
        with github_env(api="https://github.example.com/api/v3"):
            page = urllib.request.urlopen(base + "/github").read()
            self.assertIn(b"Personal account", page)
            self.assertIn(b'name="account" value="user" checked', page)
            self.assertIn(b"For a personal account, type the user login.", page)
            form = urllib.parse.urlencode(
                {"account": "user", "login": "chethankumblekar"}
            ).encode()
            manifest = urllib.request.Request(
                base + "/api/github/manifest",
                data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(manifest) as response:
                created = response.read().decode()
            self.assertIn("/settings/apps/new?state=", created)
            self.assertNotIn("/organizations/chethankumblekar/", created)
            self.assertFalse(any("/users/" in url for url in calls))
            directory = data / "github-app"
            (directory / "app.json").write_text(
                json.dumps(
                    {
                        "id": 15,
                        "slug": "checkstead",
                        "organization": "chethankumblekar",
                        "accountType": "User",
                    }
                ),
                encoding="utf-8",
            )
            (directory / "private-key.pem").write_text(self.pem, encoding="utf-8")
            (directory / "installation.json").write_text(
                json.dumps(
                    {"id": 77, "organization": "chethankumblekar", "accountType": "User"}
                ),
                encoding="utf-8",
            )
            scan = urllib.request.Request(
                base + "/api/github/scan",
                data=b"{}",
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(scan) as response:
                body = json.load(response)
        report = Path(body["scans"][0]["report"])
        self.assertEqual(report.parent.parent, scans.resolve())
        self.assertTrue(str(report).startswith(str(scans.resolve())))
        self.assertIn("branch: main", report.read_text(encoding="utf-8"))
        grouped = load_history(scans)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0].branch, "main")
        self.assertEqual(grouped[0].project, "chethankumblekar/demo")

    def test_server_entrypoint_enables_localhost_sign_in_and_persists_scans(self) -> None:
        script = (ROOT / "scripts" / "server-entrypoint.sh").read_text(encoding="utf-8")
        dockerfile = (ROOT / "Dockerfile.server").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('export CHECKSTEAD_LOCAL=1', script)
        self.assertIn("su -p", script)
        self.assertIn("/var/lib/checkstead/scans", script)
        self.assertNotIn("/opt/checkstead/scans", script)
        self.assertIn("CHECKSTEAD_LOCAL=1", dockerfile)
        self.assertIn("CHECKSTEAD_SCANS=/var/lib/checkstead/scans", dockerfile)
        self.assertIn("python -m pip install --no-cache-dir /opt/checkstead-src", dockerfile)
        self.assertLess(
            dockerfile.index("python -m pip install --no-cache-dir /opt/checkstead-src"),
            dockerfile.index("shutil.rmtree(root / 'pip')"),
        )
        self.assertIn("pip-*.dist-info", dockerfile)
        self.assertIn("rm -f /usr/local/bin/pip", dockerfile)
        self.assertIn("checkstead-scans:/var/lib/checkstead/scans", compose)
        self.assertIn("CHECKSTEAD_SCANS: /var/lib/checkstead/scans", compose)
        subprocess.run(["bash", "-n", str(ROOT / "scripts" / "server-entrypoint.sh")], check=True)
        self.assertIn("http://127.0.0.1:8765/api/sso/github/callback", readme)
        self.assertIn("docker compose up -d", readme)
        self.assertIn("http://127.0.0.1:8765/", readme)
        self.assertIn("Sign in on this computer", readme)
        self.assertIn("chethankumblekar", readme)
        self.assertIn("security-events: write", readme)
        self.assertIn("checkstead-report/checkstead.sarif", readme)
        self.assertNotIn("need an app registration", readme)
        self.assertNotIn("paste", readme.lower())
        self.assertIn("queued, in progress, success, or failure", readme)
        self.assertIn("There is no token field.", readme)

    def test_timeline_lists_checkstead_runs_and_reruns_with_stored_credentials(self) -> None:
        root = self._work("runs")
        data = root / "data"
        scans = root / "scans"
        scans.mkdir()
        self._store_app(data)
        (data / "github-app" / "installation.json").write_text(
            json.dumps({"id": 42, "organization": "acme", "accountType": "Organization"}),
            encoding="utf-8",
        )
        workflow = base64.b64encode(
            b"name: Scan\non: [pull_request]\njobs:\n  scan:\n    steps:\n"
            b"      - uses: chethankumblekar/dependency-check-db-cache@main\n"
        ).decode("ascii")
        calls: list[tuple[str, str]] = []

        def transport(method: str, url: str, headers: dict, body):
            calls.append((method, url))
            self.assertNotIn("ghs_test", url)
            self.assertNotIn("services.nvd.nist.gov", url)
            token = headers.get("Authorization", "")
            self.assertTrue(token.startswith("Bearer "))
            self.assertNotIn("PRIVATE KEY", token)
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_test"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps(
                    {"repositories": [{"full_name": "acme/widget", "default_branch": "main"}]}
                ).encode()
            if url.endswith("/contents/.github/workflows/scan.yml"):
                return 200, json.dumps({"content": workflow}).encode()
            if url.endswith("/contents/.github/workflows/ci.yml"):
                return 200, json.dumps(
                    {"content": base64.b64encode(b"name: CI\njobs: {}\n").decode("ascii")}
                ).encode()
            if url.endswith("/actions/runs?per_page=20"):
                return 200, json.dumps(
                    {
                        "workflow_runs": [
                            {
                                "id": 1,
                                "name": "Checkstead",
                                "path": ".github/workflows/checkstead.yml",
                                "status": "queued",
                                "conclusion": None,
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:01:00Z",
                            },
                            {
                                "id": 2,
                                "name": "Checkstead",
                                "path": ".github/workflows/checkstead.yml",
                                "status": "in_progress",
                                "conclusion": None,
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:02:00Z",
                            },
                            {
                                "id": 3,
                                "name": "Checkstead",
                                "path": ".github/workflows/checkstead.yml",
                                "status": "completed",
                                "conclusion": "success",
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:03:00Z",
                            },
                            {
                                "id": 4,
                                "name": "Checkstead",
                                "path": ".github/workflows/checkstead.yml",
                                "status": "completed",
                                "conclusion": "failure",
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:04:00Z",
                            },
                            {
                                "id": 5,
                                "name": "Scan",
                                "path": ".github/workflows/scan.yml",
                                "status": "completed",
                                "conclusion": "success",
                                "head_branch": "feature",
                                "event": "pull_request",
                                "pull_requests": [{"number": 12}],
                                "updated_at": "2026-10-16T00:05:00Z",
                            },
                            {
                                "id": 6,
                                "name": "CI",
                                "path": ".github/workflows/ci.yml",
                                "status": "completed",
                                "conclusion": "failure",
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:06:00Z",
                            },
                            {
                                "id": 7,
                                "name": "Checkstead",
                                "path": ".github/workflows/checkstead.yml",
                                "status": "completed",
                                "conclusion": "skipped",
                                "head_branch": "main",
                                "pull_requests": [],
                                "updated_at": "2026-10-16T00:00:00Z",
                            },
                        ]
                    }
                ).encode()
            if url.endswith("/actions/runs/5"):
                return 200, json.dumps(
                    {
                        "id": 5,
                        "name": "Scan",
                        "path": ".github/workflows/scan.yml",
                        "status": "completed",
                        "conclusion": "success",
                        "head_branch": "feature",
                        "pull_requests": [{"number": 12}],
                    }
                ).encode()
            if url.endswith("/actions/runs/6"):
                return 200, json.dumps(
                    {
                        "id": 6,
                        "name": "CI",
                        "path": ".github/workflows/ci.yml",
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ).encode()
            if url.endswith("/actions/runs/5/rerun"):
                self.assertEqual(method, "POST")
                self.assertIsNone(body)
                return 201, b""
            raise AssertionError(url)

        with github_env(api="https://github.example.com/api/v3"):
            listed = list_workflow_runs(data, transport)
        self.assertTrue(listed["connected"])
        self.assertEqual(
            [(run["id"], run["status"]) for run in listed["runs"]],
            [(5, "success"), (4, "failure"), (3, "success"), (2, "in progress"), (1, "queued")],
        )
        pull = listed["runs"][0]
        self.assertEqual(pull["pullRequest"], 12)
        self.assertEqual(pull["pullRequestUrl"], "https://github.example.com/acme/widget/pull/12")
        self.assertEqual(pull["repository"], "acme/widget")
        self.assertNotIn("ghs_test", json.dumps(listed))

        calls.clear()
        with github_env(api="https://github.example.com/api/v3"):
            started = rerun_workflow(data, "acme/widget", 5, transport)
        self.assertEqual(started, {"repository": "acme/widget", "id": 5, "status": "queued"})
        self.assertIn(
            ("POST", "https://github.example.com/api/v3/repos/acme/widget/actions/runs/5/rerun"),
            calls,
        )
        self.assertNotIn("ghs_test", json.dumps(started))
        with github_env(api="https://github.example.com/api/v3"):
            with self.assertRaises(ChecksteadError) as refused:
                rerun_workflow(data, "acme/widget", 6, transport)
        self.assertIn("Checkstead", str(refused.exception))

        def denied(method: str, url: str, headers: dict, body):
            calls.append((method, url, body))
            if url.endswith("/access_tokens"):
                return 201, json.dumps({"token": "ghs_test"}).encode()
            if "/installation/repositories" in url:
                return 200, json.dumps({"repositories": [{"full_name": "acme/widget"}]}).encode()
            if url.endswith("/actions/runs?per_page=20"):
                return 403, b'{"message":"Resource not accessible by integration"}'
            if url.endswith("/app"):
                if method == "GET":
                    return 200, json.dumps({"permissions": {"contents": "read", "metadata": "read"}}).encode()
                self.assertEqual(method, "PATCH")
                self.assertIn(b'"actions": "write"', body)
                self.assertNotIn(b"PRIVATE KEY", body)
                return 200, b"{}"
            raise AssertionError((method, url))

        calls.clear()
        with github_env(api="https://github.example.com/api/v3"):
            with self.assertRaises(ActionsPermissionRequired) as needed:
                list_workflow_runs(data, denied)
        self.assertIn("Actions", str(needed.exception))
        self.assertNotIn("token", str(needed.exception).lower())
        self.assertEqual(
            needed.exception.approval_url,
            "https://github.example.com/organizations/acme/settings/installations/42",
        )

        server = bind_server(scans, "127.0.0.1", 0, data, github_transport=transport)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        host, port = server.server_address[:2]
        base = f"http://{host}:{port}"

        def request(path: str, method: str = "GET", data_bytes: bytes | None = None):
            req = urllib.request.Request(
                base + path,
                data=data_bytes,
                headers={"Content-Type": "application/json"} if data_bytes else {},
                method=method,
            )
            try:
                with urllib.request.urlopen(req) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read()

        with github_env(api="https://github.example.com/api/v3"):
            status, body = request("/api/github/runs")
            self.assertEqual(status, 200, body.decode())
            payload = json.loads(body)
            self.assertEqual(payload["runs"][0]["pullRequest"], 12)
            self.assertNotIn(b"ghs_test", body)
            self.assertNotIn(b"PRIVATE KEY", body)
            status, body = request(
                "/api/github/rerun",
                "POST",
                json.dumps({"repository": "acme/widget", "run": 5}).encode(),
            )
            self.assertEqual(status, 202, body.decode())
            self.assertEqual(json.loads(body)["status"], "queued")
            self.assertNotIn(b"ghs_test", body)
            self.assertNotIn(b"token", body.lower())

        page = (ROOT / "src" / "checkstead" / "ui_page.html").read_text(encoding="utf-8")
        self.assertIn('id="builds"', page)
        self.assertIn("Rerun", page)
        self.assertIn("pullRequestUrl", page)
        self.assertIn("Direct · Production", page)
        self.assertIn("Direct · Dev", page)
        self.assertIn("Transitive · Production", page)
        self.assertIn("Transitive · Dev", page)
        self.assertNotIn('name="token"', page)
        self.assertNotIn("personal access", page.lower())
