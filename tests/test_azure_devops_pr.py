"""The one Checkstead thread on an Azure Repos pull request.

No vulnerability feed is contacted. The comment step talks to a local stand-in
for the Azure DevOps pull request threads API.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import TestCase
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.score import COMMENT_MARKER  # noqa: E402

SCRIPT = ROOT / "scripts" / "ado-pr-comment.py"
PROJECT = "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c"
REPOSITORY = "3411ebc1-d5aa-464f-9615-0b527bc66719"
THREADS = f"/org/{PROJECT}/_apis/git/repositories/{REPOSITORY}/pullRequests/42/threads"


class AzureDevOpsPullRequestCommentTest(TestCase):
    def setUp(self) -> None:
        self.server = _ThreadServer()
        self.addCleanup(self.server.close)
        self.comment = ROOT / "build" / "tests" / "ado-comment.md"
        self.comment.parent.mkdir(parents=True, exist_ok=True)
        self.comment.write_text(f"{COMMENT_MARKER}\nCheckstead pull request #42\n", encoding="utf-8")
        self.env = os.environ.copy()
        self.env.update(
            {
                "SYSTEM_ACCESSTOKEN": "pipeline-token",
                "SYSTEM_COLLECTIONURI": f"{self.server.url}/org/",
                "SYSTEM_TEAMPROJECTID": PROJECT,
                "BUILD_REPOSITORY_ID": REPOSITORY,
                "SYSTEM_PULLREQUEST_PULLREQUESTID": "42",
                "COMMENT_FILE": str(self.comment),
            }
        )

    def _run(self, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            env=env or self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_creates_one_closed_thread_then_updates_it(self) -> None:
        first = self._run()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.comment.write_text(
            f"{COMMENT_MARKER}\nCheckstead pull request #42\nupdated\n", encoding="utf-8"
        )
        second = self._run()
        self.assertEqual(second.returncode, 0, second.stderr)

        self.assertEqual(len(self.server.threads), 1)
        thread = self.server.threads[0]
        self.assertEqual(thread["status"], 4)
        self.assertIn("updated", thread["comments"][0]["content"])
        self.assertEqual(self.server.methods, ["GET", "POST", "GET", "PATCH"])
        self.assertTrue(all(path == THREADS or path.startswith(THREADS + "/") for path in self.server.paths))
        self.assertTrue(all(query == "api-version=7.1" for query in self.server.queries))
        self.assertTrue(all(item == "Bearer pipeline-token" for item in self.server.authorizations))
        self.assertNotIn("pipeline-token", first.stdout + first.stderr + second.stdout + second.stderr)

    def test_updates_the_marked_comment_and_skips_deleted_ones(self) -> None:
        self.server.threads.extend(
            [
                {"id": 3, "status": 1, "comments": [{"id": 1, "content": "a reviewer note"}]},
                {"id": 4, "isDeleted": True, "comments": [{"id": 1, "content": COMMENT_MARKER}]},
                {"id": 9, "status": 4, "comments": [{"id": 2, "content": f"{COMMENT_MARKER}\nold"}]},
            ]
        )
        completed = self._run()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("POST", self.server.methods)
        self.assertEqual(self.server.patched, (9, 2))

    def test_outside_a_pull_request_build_it_does_nothing(self) -> None:
        env = dict(self.env)
        del env["SYSTEM_PULLREQUEST_PULLREQUESTID"]
        completed = self._run(env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.server.methods, [])

    def test_without_the_mapped_token_it_does_nothing(self) -> None:
        env = dict(self.env)
        env["SYSTEM_ACCESSTOKEN"] = ""
        completed = self._run(env)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(self.server.methods, [])

    def test_refuses_values_that_would_change_the_request_path(self) -> None:
        cases = {
            "SYSTEM_TEAMPROJECTID": "../other",
            "BUILD_REPOSITORY_ID": "repo/../../x",
            "SYSTEM_PULLREQUEST_PULLREQUESTID": "42/../7",
            "SYSTEM_COLLECTIONURI": "http://dev.azure.com/org/",
        }
        for name, value in cases.items():
            with self.subTest(name=name):
                env = dict(self.env)
                env[name] = value
                completed = self._run(env)
                self.assertEqual(completed.returncode, 1)
                self.assertIn(name, completed.stderr)
        self.assertEqual(self.server.methods, [])

    def test_the_script_takes_the_token_only_from_the_pipeline(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("SYSTEM_ACCESSTOKEN", script)
        self.assertNotIn("input(", script)
        self.assertNotIn("paste", script.lower())
        self.assertNotIn("services.nvd.nist.gov", script)
        example = (ROOT / "integrations" / "azure-devops" / "pull-request.yml").read_text(encoding="utf-8")
        self.assertIn("SYSTEM_ACCESSTOKEN: $(System.AccessToken)", example)
        self.assertIn("--pull-request", example)
        self.assertNotIn("NVD_API_KEY", example)
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("COPY scripts/ado-pr-comment.py /usr/local/bin/checkstead-ado-comment", dockerfile)
        self.assertIn("/usr/local/bin/checkstead-ado-comment", example)


class _ThreadServer:
    def __init__(self) -> None:
        outer = self
        self.threads: list[dict] = []
        self.methods: list[str] = []
        self.paths: list[str] = []
        self.queries: list[str] = []
        self.authorizations: list[str] = []
        self.patched: tuple[int, int] | None = None

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._record("GET")
                self._json({"value": outer.threads, "count": len(outer.threads)})

            def do_POST(self):
                self._record("POST")
                payload = self._body()
                thread = {"id": 11, "status": payload.get("status"), "comments": []}
                for index, comment in enumerate(payload.get("comments", []), start=1):
                    thread["comments"].append({"id": index, "content": comment["content"]})
                outer.threads.append(thread)
                self._json(thread)

            def do_PATCH(self):
                self._record("PATCH")
                payload = self._body()
                parts = urlparse(self.path).path.rstrip("/").split("/")
                thread_id, comment_id = int(parts[-3]), int(parts[-1])
                outer.patched = (thread_id, comment_id)
                for thread in outer.threads:
                    if thread["id"] == thread_id:
                        for comment in thread["comments"]:
                            if comment["id"] == comment_id:
                                comment["content"] = payload["content"]
                self._json({"id": comment_id, "content": payload["content"]})

            def _record(self, method: str) -> None:
                parsed = urlparse(self.path)
                outer.methods.append(method)
                outer.paths.append(parsed.path)
                outer.queries.append(parsed.query)
                outer.authorizations.append(self.headers.get("Authorization", ""))

            def _body(self) -> dict:
                length = int(self.headers.get("Content-Length", "0"))
                return json.loads(self.rfile.read(length).decode("utf-8"))

            def _json(self, payload) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, fmt, *args):
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        host, port = self._httpd.server_address[:2]
        self.url = f"http://{host}:{port}"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
