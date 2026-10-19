"""A version tag releases the GitHub Action and the Azure DevOps extension."""

from __future__ import annotations

import importlib.util
import json
import struct
import subprocess
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.release import (  # noqa: E402
    is_release_candidate,
    moving_tags,
    parse_tag,
    release_image,
    release_notes,
    scanner_image,
)


def _load_stamp():
    path = ROOT / "scripts" / "package-azure-extension.py"
    spec = importlib.util.spec_from_file_location("package_azure_extension", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.stamp


stamp = _load_stamp()


class ReleaseTests(TestCase):
    def test_a_version_tag_names_the_floating_tags_and_the_image(self) -> None:
        parts = parse_tag("v0.1.0")
        self.assertEqual(parts, (0, 1, 0))
        self.assertEqual(moving_tags(parts), ("v0", "v0.1"))
        self.assertEqual(
            scanner_image(parts),
            "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:0.1.0",
        )
        with self.assertRaises(ValueError):
            parse_tag("0.1.0")
        with self.assertRaises(ValueError):
            parse_tag("v0.1.1-rc.1")
        self.assertTrue(is_release_candidate("v0.1.1-rc.1"))
        self.assertFalse(is_release_candidate("v0.1.0"))
        self.assertEqual(
            release_image("v0.1.1-rc.1"),
            "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:v0.1.1-rc.1",
        )
        candidate = release_notes("v0.1.1-rc.1")
        self.assertIn("release candidate", candidate)
        self.assertIn("does not move `latest`", candidate)
        self.assertNotIn("point at this release", candidate)
        refused = subprocess.run(
            ["bash", str(ROOT / "scripts" / "move-release-tags.sh"), "v0.1.1-rc.1"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertIn("does not move floating tags", refused.stderr)

    def test_release_notes_name_both_marketplaces_and_no_api_key(self) -> None:
        notes = release_notes("v1.2.3")
        self.assertIn("Publish this Action to the GitHub Marketplace", notes)
        self.assertIn("Security", notes)
        self.assertIn("ChecksteadScan@1", notes)
        self.assertIn("The release pipeline publishes this public extension", notes)
        self.assertIn("does not take an NVD API key", notes)
        self.assertNotIn("Upload the VSIX", notes)
        self.assertIn(
            "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
            notes,
        )
        self.assertNotIn("nvdApiKey", notes)

    def test_the_task_runs_docker_without_an_api_key(self) -> None:
        script = ROOT / "integrations" / "azure-devops" / "task" / "index.js"
        probe = subprocess.run(
            [
                "node",
                "-e",
                "const {buildArgs} = require(process.argv[1]);"
                "const args = buildArgs('/src', {scan: '.', project: 'demo', output: 'out',"
                " config: 'checkstead.yml', image: 'ghcr.io/example/checkstead:0.1.0'});"
                "if (args[0] !== 'run' || !args.includes('scan') || !args.includes('--scan')) process.exit(2);"
                "if (!args.includes('--user')) process.exit(5);"
                "if (!/^\\d+:\\d+$/.test(args[args.indexOf('--user') + 1])) process.exit(6);"
                "if (args.some((item) => /nvd/i.test(item))) process.exit(3);"
                "try { buildArgs('/src', {scan: '../secret', output: 'out', image: 'img'}); process.exit(4); }"
                "catch (error) {}",
                str(script),
            ],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        text = script.read_text(encoding="utf-8")
        self.assertNotIn("NVD_API_KEY", text)
        self.assertNotIn("nvdApiKey", text)

    def test_stamp_sets_the_extension_version_and_image(self) -> None:
        dest = ROOT / "build" / "tests" / "azure-extension"
        stamp(dest, "v0.2.0", "example-publisher")
        manifest = json.loads((dest / "vss-extension.json").read_text(encoding="utf-8"))
        task = json.loads((dest / "task" / "task.json").read_text(encoding="utf-8"))
        index = (dest / "task" / "index.js").read_text(encoding="utf-8")
        self.assertEqual(manifest["version"], "0.2.0")
        self.assertEqual(manifest["publisher"], "example-publisher")
        self.assertIs(manifest["public"], True)
        self.assertEqual(task["version"], {"Major": 0, "Minor": 2, "Patch": 0})
        image = "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:0.2.0"
        self.assertEqual(
            next(item["defaultValue"] for item in task["inputs"] if item["name"] == "image"),
            image,
        )
        self.assertIn(image, index)
        self.assertNotIn("nvdApiKey", json.dumps(task))

    def test_the_release_workflow_publishes_both_packages(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        manifest = json.loads(
            (ROOT / "integrations" / "azure-devops" / "vss-extension.json").read_text(encoding="utf-8")
        )
        self.assertIn('tags:\n      - "v[0-9]+.[0-9]+.[0-9]+"', workflow)
        self.assertIn('"v[0-9]+.[0-9]+.[0-9]+-rc.[0-9]+"', workflow)
        self.assertIn("--prerelease", workflow)
        self.assertIn("--latest=false", workflow)
        self.assertIn("!contains(github.ref_name, '-rc.')", workflow)
        self.assertIn("gh release create", workflow)
        self.assertIn("scripts/move-release-tags.sh", workflow)
        self.assertIn("scripts/package-azure-extension.py", workflow)
        self.assertIn("scripts/publish-azure-extension.sh", workflow)
        self.assertIn("Publish to the Azure DevOps Marketplace", workflow)
        self.assertIn("secrets.AZURE_MARKETPLACE_TOKEN", workflow)
        self.assertIn("vars.AZURE_MARKETPLACE_PUBLISHER", workflow)
        self.assertNotIn("nvdApiKey", workflow)
        self.assertIn("branding:", action)
        self.assertIn("icon: \"shield\"", action)
        self.assertNotIn("nvdApiKey", action)
        self.assertEqual(manifest["contributions"][0]["type"], "ms.vss-distributed-task.task")
        self.assertIs(manifest["public"], True)
        icon = (ROOT / "integrations" / "azure-devops" / "images" / "icon.png").read_bytes()
        self.assertEqual(icon[12:16], b"IHDR")
        width, height = struct.unpack(">II", icon[16:24])
        self.assertGreaterEqual(width, 128)
        self.assertGreaterEqual(height, 128)
        missing = subprocess.run(
            ["bash", str(ROOT / "scripts" / "publish-azure-extension.sh"), "missing.vsix"],
            check=False,
            text=True,
            capture_output=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(missing.returncode, 1, missing.stdout + missing.stderr)
        self.assertIn("The release pipeline publishes this extension.", missing.stderr)
        self.assertIn("AZURE_MARKETPLACE_TOKEN", missing.stderr)
        self.assertIn("AZURE_MARKETPLACE_PUBLISHER", missing.stderr)
