"""Source SBOM and local release validation stay inside this repository."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.engine import pinned_engine  # noqa: E402


class SupplyChainTests(TestCase):
    def test_source_sbom_names_certifi_and_the_engine_pin(self) -> None:
        destination = ROOT / "build" / "tests" / "sbom" / "checkstead.cdx.json"
        subprocess.run(["rm", "-rf", str(destination.parent)], check=True)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "write-sbom.py"), str(destination)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        document = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")
        self.assertEqual(document["metadata"]["component"]["name"], "checkstead")
        names = {item["name"]: item for item in document["components"]}
        self.assertEqual(names["dependency-check"]["version"], pinned_engine())
        self.assertIn("pkg:pypi/certifi@", names["certifi"]["purl"])
        self.assertNotEqual(names["certifi"]["version"], "uninstalled")
        self.assertNotIn("signed", destination.read_text(encoding="utf-8").lower())

    def test_release_validation_script_does_not_publish(self) -> None:
        script = (ROOT / "scripts" / "check-release.sh").read_text(encoding="utf-8")
        images = (ROOT / "scripts" / "scan-images.sh").read_text(encoding="utf-8")
        self.assertNotIn("gh release", script)
        self.assertNotIn("docker push", script)
        self.assertIn("write-sbom.py", script)
        self.assertIn("did not publish", script)
        self.assertNotIn("docker push", images)
        self.assertIn("exit 2", images)
        self.assertIn("--exit-code 1", images)
        dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        for ecosystem in ("pip", "github-actions", "docker", "maven"):
            self.assertIn(f"package-ecosystem: {ecosystem}", dependabot)

    def test_local_sign_in_warning_is_in_the_server_entrypoint(self) -> None:
        script = (ROOT / "scripts" / "server-entrypoint.sh").read_text(encoding="utf-8")
        page = (ROOT / "src" / "checkstead" / "ui.py").read_text(encoding="utf-8")
        warning = "CHECKSTEAD_LOCAL=1 lets any client that can reach this port"
        self.assertIn(warning, script)
        self.assertIn(warning, page)
        self.assertIn("127.0.0.1:8765:8765", script)
