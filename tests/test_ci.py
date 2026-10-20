"""CI lints and tests before it publishes tagged container images."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

_SHA_PIN = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}$")
_PIN_COMMENT = re.compile(r"@[0-9a-f]{40}\s+#\s+v\d")


def _assert_action_pins(test: TestCase, text: str, name: str) -> None:
    """A reviewed SHA bump stays green. A floating tag does not."""
    test.assertNotRegex(text, r"uses:\s+\S+@v\d", name)
    found = False
    for line in text.splitlines():
        if "uses:" not in line:
            continue
        match = re.search(r"uses:\s+(\S+)", line)
        test.assertIsNotNone(match, f"{name}: {line}")
        assert match is not None
        test.assertRegex(match.group(1), _SHA_PIN, f"{name}: {line}")
        test.assertRegex(line, _PIN_COMMENT, f"{name}: {line}")
        found = True
    test.assertTrue(found, name)


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
        self.assertIn(".[dev]", ci)
        self.assertNotRegex(ci, r"ruff==[0-9]")
        self.assertNotRegex(ci, r"build==[0-9]")
        self.assertIn("packages: write", ci)
        self.assertIn("id-token: write", ci)
        self.assertIn("attestations: write", ci)
        self.assertIn("provenance: mode=max", ci)
        self.assertIn("sbom: true", ci)
        self.assertIn("provenance: false", ci)
        self.assertIn("load: true", ci)
        self.assertIn("push: false", ci)
        self.assertIn("ghcr.io/${GITHUB_REPOSITORY}/", ci)
        self.assertIn("image: checkstead-server", ci)
        self.assertIn("file: Dockerfile", ci)
        self.assertIn("file: Dockerfile.server", ci)
        self.assertIn("github.event_name != 'pull_request'", ci)
        self.assertIn("github.event.repository.default_branch", ci)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", ci)
        # One gate policy, in one script, for pull requests and for publishing.
        gates_script = (ROOT / "scripts" / "image-gates.sh").read_text(encoding="utf-8")
        self.assertEqual(ci.count("bash ./scripts/image-gates.sh"), 2)
        # The engine is gated too. Its vulnerable jars are replaced, not skipped.
        self.assertNotIn("--skip-dirs", gates_script)
        overrides = (ROOT / "scripts" / "engine-overrides.txt").read_text(encoding="utf-8")
        self.assertRegex(overrides, r"(?m)^jackson-databind-[0-9.]+\.jar \S+ [0-9a-f]{64}$")
        self.assertIn("--severity CRITICAL,HIGH --pkg-types library", gates_script)
        self.assertIn("--severity CRITICAL,HIGH --pkg-types os", gates_script)
        self.assertIn("--ignore-unfixed --exit-code 1", gates_script)
        commands = "\n".join(
            line for line in gates_script.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertEqual(commands.count("--ignore-unfixed"), 1)
        library_gate = commands[commands.index("--pkg-types library") : commands.index("--pkg-types os")]
        self.assertNotIn("--ignore-unfixed", library_gate)
        self.assertEqual(gates_script.count("--exit-code 1"), 2)
        self.assertIn("Exception unfixed-os-2026-10-19", gates_script)
        self.assertIn("2027-01-19", gates_script)
        self.assertIn("CVE-2025-7458", gates_script)
        self.assertIn("CVE-2023-45853", gates_script)
        self.assertIn("This is not a .trivyignore file.", gates_script)
        self.assertNotIn(".trivyignore", ci)
        self.assertFalse((ROOT / ".trivyignore").exists())
        gates = (ROOT / "docs" / "security" / "security-gates.md").read_text(encoding="utf-8")
        self.assertIn("unfixed-os-2026-10-19", gates)
        self.assertIn("2027-01-19", gates)
        images = (ROOT / "scripts" / "scan-images.sh").read_text(encoding="utf-8")
        self.assertIn("unfixed-os-2026-10-19", images)
        self.assertIn("scripts/image-gates.sh", images)
        self.assertIn("type=semver,pattern={{version}},enable=${{ !contains(github.ref_name, '-') }}", ci)
        self.assertIn("type=semver,pattern={{major}}.{{minor}},enable=${{ !contains(github.ref_name, '-') }}", ci)
        self.assertRegex(
            ci,
            r"actions/attest-build-provenance@[0-9a-f]{40} # v\d",
        )
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", ci)
        images, _marker, publish = ci.partition("publish-images:")
        self.assertIn("push-to-registry: true", publish)
        # The publish job pushes only the immutable candidate tag, gates the
        # pushed digest, attests it, and only then moves the other tags.
        self.assertIn("tags: ${{ steps.pin.outputs.name }}:sha-${{ github.sha }}", publish)
        order = [
            "name: Build and push the candidate",
            'image-gates.sh "${{ matrix.kind }}" "${{ steps.pin.outputs.name }}@${{ steps.push.outputs.digest }}"',
            "name: Attest image provenance",
            "name: Verify the GitHub provenance attestation",
            "name: Promote the gated digest",
        ]
        positions = [publish.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("PLATFORMS: ${{ matrix.platforms }}", publish)
        self.assertIn("no-cache: ${{ startsWith(github.ref, 'refs/tags/') }}", publish)
        self.assertNotIn("packages: write", images)
        self.assertIn("packages: write", publish)
        self.assertIn("push: false", images)
        self.assertIn("type=sha,format=long,prefix=sha-", ci)
        self.assertIn("type=ref,event=branch", ci)
        self.assertIn("type=ref,event=tag", ci)
        self.assertIn("type=semver,pattern={{version}}", ci)
        self.assertIn("type=semver,pattern={{major}}.{{minor}}", ci)
        self.assertIn("value=latest,enable={{is_default_branch}}", ci)
        self.assertIn("value=engine-", ci)
        self.assertRegex(ci, r"docker/metadata-action@[0-9a-f]{40} # v\d")
        build_push = re.findall(r"docker/build-push-action@([0-9a-f]{40}) # v\d", ci)
        self.assertEqual(len(build_push), 2)
        self.assertEqual(build_push[0], build_push[1])
        self.assertIn("linux/amd64,linux/arm64", ci)
        self.assertRegex(ci, r"docker/setup-qemu-action@[0-9a-f]{40} # v\d")
        self.assertRegex(ci, r"aquasecurity/setup-trivy@[0-9a-f]{40} # v\d")
        self.assertIn("TRIVY_VERSION: v", ci)
        self.assertEqual(ci.count("persist-credentials: false"), 3)
        self.assertNotRegex(ci, r"uses: .+@v\d+")
        for workflow in workflows.glob("*.yml"):
            text = workflow.read_text(encoding="utf-8")
            _assert_action_pins(self, text, workflow.name)
        self.assertFalse((workflows / "update-db.yml").exists())
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        example = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead-server:latest", compose)
        self.assertIn("restart: unless-stopped", compose)
        self.assertIn("127.0.0.1:8765:8765", compose)
        self.assertIn("checkstead-data:", compose)
        self.assertIn("env_file:", compose)
        for name in (
            "CHECKSTEAD_GITHUB_CLIENT_ID",
            "CHECKSTEAD_GITHUB_CLIENT_SECRET",
            "CHECKSTEAD_ENTRA_CLIENT_ID",
            "CHECKSTEAD_ENTRA_CLIENT_SECRET",
            "CHECKSTEAD_ENTRA_TENANT",
        ):
            self.assertIn(name, example)
        self.assertNotIn("paste", example.lower())

        self.assertIn("ruff check src tests", script)
        self.assertIn("python3 -m compileall -q src tests", script)
        self.assertIn("bash -n", script)
        self.assertIn("python3 -m unittest discover -s tests -v", script)
        self.assertIn("python3 -m build --wheel", script)
        self.assertIn("mvn -B -f integrations/maven/pom.xml verify", script)
        self.assertRegex(project, r'"ruff==[0-9]+\.[0-9]+\.[0-9]+"')
        self.assertRegex(project, r'"build==[0-9]+\.[0-9]+\.[0-9]+"')
        self.assertIn('"certifi>=', project)
        self.assertIn('"cryptography>=', project)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("actions/workflows/ci.yml/badge.svg?branch=main", readme)
        self.assertIn("docs/screenshots/sign-in.png", readme)
        self.assertIn("docs/screenshots/scan.png", readme)
        self.assertIn("docs/screenshots/drift.png", readme)
        self.assertIn("docs/screenshots/administration.png", readme)
        self.assertIn("```mermaid", readme)
        self.assertIn("Chethan K", readme)
        shots = ROOT / "docs" / "screenshots"
        for shot in ("sign-in.png", "scan.png", "drift.png", "administration.png"):
            self.assertTrue((shots / shot).is_file())
        self.assertNotEqual((shots / "sign-in.png").read_bytes(), (shots / "drift.png").read_bytes())
        self.assertNotEqual((shots / "scan.png").read_bytes(), (shots / "drift.png").read_bytes())

    def test_codeql_uploads_sarif_for_pull_requests_and_main(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("branches:\n      - main", workflow)
        self.assertIn("security-events: write", workflow)
        self.assertIn("languages: python", workflow)
        self.assertIn("upload: true", workflow)
        self.assertNotIn("upload: false", workflow)
        self.assertNotIn("continue-on-error", workflow)
        _assert_action_pins(self, workflow, "codeql.yml")

    def test_build_push_action_pin_matches_both_jobs_and_the_record(self) -> None:
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        record = (ROOT / "docs" / "security" / "supply-chain-and-provenance.md").read_text(encoding="utf-8")
        pins = re.findall(r"docker/build-push-action@([0-9a-f]{40}) # v\d", ci)
        self.assertEqual(len(pins), 2)
        self.assertEqual(pins[0], pins[1])
        self.assertNotIn("docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8", ci)
        self.assertIn("workflow file is the pin", record)
