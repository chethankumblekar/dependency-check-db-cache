"""CI lints and tests before it publishes tagged container images."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class CiTests(TestCase):
    def test_pushes_publish_tagged_images_after_the_self_test(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        self.assertFalse((workflows / "test.yml").exists())
        self.assertFalse((workflows / "image.yml").exists())
        ci = (workflows / "ci.yml").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "self-test.sh").read_text(encoding="utf-8")
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("push:", ci)
        self.assertIn("pull_request:", ci)
        self.assertIn("needs: test", ci)
        self.assertIn("bash ./scripts/self-test.sh", ci)
        self.assertIn("ruff==0.14.2", ci)
        self.assertIn("build==1.3.0", ci)
        self.assertIn("packages: write", ci)
        self.assertIn("ghcr.io/${{ github.repository }}/", ci)
        self.assertIn("image: checkstead-server", ci)
        self.assertIn("file: Dockerfile", ci)
        self.assertIn("file: Dockerfile.server", ci)
        self.assertIn("github.event_name != 'pull_request'", ci)
        self.assertIn("type=sha,format=long,prefix=sha-", ci)
        self.assertIn("type=ref,event=branch", ci)
        self.assertIn("type=ref,event=tag", ci)
        self.assertIn("type=semver,pattern={{version}}", ci)
        self.assertIn("type=semver,pattern={{major}}.{{minor}}", ci)
        self.assertIn("value=latest,enable={{is_default_branch}}", ci)
        self.assertIn("value=engine-", ci)
        self.assertIn("docker/metadata-action@v5", ci)
        self.assertIn("docker/build-push-action@v6", ci)

        self.assertIn("ruff check src tests", script)
        self.assertIn("python3 -m compileall -q src tests", script)
        self.assertIn("bash -n", script)
        self.assertIn("python3 -m unittest discover -s tests -v", script)
        self.assertIn("python3 -m build --wheel", script)
        self.assertIn("mvn -B -f integrations/maven/pom.xml verify", script)
        self.assertIn("ruff==0.14.2", project)
        self.assertIn("build==1.3.0", project)
        self.assertIn('dependencies = ["certifi"]', project)
        self.assertIn("certifi", ci)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("actions/workflows/ci.yml/badge.svg?branch=main", readme)
        self.assertIn("docs/screenshots/sign-in.png", readme)
        self.assertIn("docs/screenshots/drift.png", readme)
        self.assertIn("docs/screenshots/administration.png", readme)
        self.assertIn("```mermaid", readme)
        self.assertIn("Chethan K", readme)
        for shot in ("sign-in.png", "drift.png", "administration.png"):
            self.assertTrue((ROOT / "docs" / "screenshots" / shot).is_file())
