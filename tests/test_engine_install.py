"""The engine installer verifies a signature before it keeps a binary."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path
from unittest import TestCase, skipUnless

# Signing tests need gpg. CI installs it; a workstation without it reports
# these tests as skipped, never as passed.
HAVE_GPG = shutil.which("gpg") is not None
if os.environ.get("CI") and not HAVE_GPG:
    raise RuntimeError("gpg is required for the engine signature tests in CI.")

ROOT = Path(__file__).resolve().parents[1]


def _fingerprint(key_path: Path) -> str:
    shown = subprocess.run(
        ["gpg", "--batch", "--with-colons", "--show-keys", str(key_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    for line in shown.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9]
    raise AssertionError(shown.stdout)


def _generate_key(home: Path, public_key: Path) -> str:
    home.mkdir(parents=True)
    home.chmod(0o700)
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-gen-key",
            "Checkstead Test <test@example.invalid>",
            "default",
            "default",
            "0",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    exported = subprocess.run(
        ["gpg", "--batch", "--armor", "--export"],
        check=True,
        capture_output=True,
        env=env,
    )
    public_key.write_bytes(exported.stdout)
    return _fingerprint(public_key)


def _sign(home: Path, archive: Path, signature: Path) -> None:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(home)
    subprocess.run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--detach-sign",
            "--armor",
            "--output",
            str(signature),
            str(archive),
        ],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _curl_stub(directory: Path, archive: Path, signature: Path, fail: bool = False) -> None:
    if fail:
        body = "#!/bin/sh\nexit 22\n"
    else:
        body = (
            "#!/bin/sh\n"
            "out=\n"
            "prev=\n"
            "url=\n"
            'for arg in "$@"; do\n'
            '  if [ "$prev" = "-o" ]; then\n'
            "    out=$arg\n"
            "    prev=\n"
            "    continue\n"
            "  fi\n"
            '  case "$arg" in\n'
            "    -o) prev=-o ;;\n"
            "    -*) ;;\n"
            "    *) url=$arg ;;\n"
            "  esac\n"
            "done\n"
            'case "$url" in\n'
            f'  *.asc) cp "{signature}" "$out" ;;\n'
            f'  *) cp "{archive}" "$out" ;;\n'
            "esac\n"
        )
    tool = directory / "curl"
    tool.write_text(body, encoding="utf-8")
    tool.chmod(0o755)


def _engine_zip(path: Path, reported: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    info = zipfile.ZipInfo("dependency-check/bin/dependency-check.sh")
    info.external_attr = (stat.S_IFREG | 0o755) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, f"#!/bin/sh\necho {reported}\n")


@skipUnless(HAVE_GPG, "gpg is not installed")
class EngineInstallTests(TestCase):
    def _run(self, root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        # Fake engines have no library jars to patch. The override tests set this.
        env.setdefault("ENGINE_OVERRIDES", "")
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / "install-engine.sh"), str(root / "dest")],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_refuses_a_version_file_that_is_not_a_release(self) -> None:
        root = ROOT / "build" / "tests" / "engine-version"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        version = root / "engine.version"
        version.write_text("not-a-release\n", encoding="utf-8")
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["PATH"] = "/usr/bin:/bin"
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn("not a release number", completed.stderr)

    def test_refuses_a_failed_download(self) -> None:
        root = ROOT / "build" / "tests" / "engine-download"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        version = root / "engine.version"
        version.write_text("13.0.0\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, root / "missing.zip", root / "missing.asc", fail=True)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertNotEqual(completed.returncode, 0, completed.stdout)
        self.assertFalse((root / "dest" / "bin" / "dependency-check.sh").exists())

    def test_refuses_a_signature_that_does_not_verify(self) -> None:
        root = ROOT / "build" / "tests" / "engine-signature"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        version = root / "engine.version"
        version.write_text("13.0.0\n", encoding="utf-8")
        archive = root / "dc.zip"
        archive.write_bytes(b"not a signed zip")
        signature = root / "dc.zip.asc"
        signature.write_text("not a signature\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("signature does not verify", completed.stderr)
        self.assertFalse((root / "dest").exists())

    def test_refuses_a_signed_archive_whose_binary_reports_another_version(self) -> None:
        root = ROOT / "build" / "tests" / "engine-mismatch"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        _engine_zip(archive, "9.9.9")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        version = root / "engine.version"
        version.write_text("1.2.3\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("Expected 1.2.3", completed.stderr)
        self.assertFalse((root / "dest" / "bin" / "dependency-check.sh").exists())

    def test_refuses_a_signed_archive_without_the_executable(self) -> None:
        root = ROOT / "build" / "tests" / "engine-missing"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("dependency-check/README.txt", "missing binary\n")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        version = root / "engine.version"
        version.write_text("1.2.3\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("bin/dependency-check.sh", completed.stderr)

    def test_installs_a_signed_archive_that_reports_the_pin(self) -> None:
        root = ROOT / "build" / "tests" / "engine-ok"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        _engine_zip(archive, "1.2.3")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        version = root / "engine.version"
        version.write_text("1.2.3\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Installed Dependency-Check 1.2.3", completed.stdout)
        binary = root / "dest" / "bin" / "dependency-check.sh"
        self.assertTrue(binary.is_file())
        reported = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True)
        self.assertIn("1.2.3", reported.stdout)

    def test_refuses_a_signed_archive_that_tries_to_escape(self) -> None:
        root = ROOT / "build" / "tests" / "engine-slip"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../escape.txt", "nope\n")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        version = root / "engine.version"
        version.write_text("1.2.3\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertFalse((root / "escape.txt").exists())
        self.assertFalse(Path("/tmp/escape.txt").exists())

    def _setup(self, root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
        script = root / "run-setup.sh"
        lines = [
            "set -euo pipefail",
            f"source {ROOT / 'scripts' / 'setup.sh'}",
            f"PIN={env['PIN']}",
            f"ROOT={root / 'home' / 'checkstead'}",
            f"python={env['python']}",
            "install_engine",
        ]
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return subprocess.run(
            ["bash", str(script)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_setup_sh_refuses_a_signature_that_does_not_verify(self) -> None:
        root = ROOT / "build" / "tests" / "setup-engine-bad-signature"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        archive = root / "dc.zip"
        archive.write_bytes(b"not a signed zip")
        signature = root / "dc.zip.asc"
        signature.write_text("not a signature\n", encoding="utf-8")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["PIN"] = "13.0.0"
        env["python"] = "/usr/bin/python3"
        env["PATH"] = str(stub) + os.pathsep + "/usr/bin:/bin"
        env.pop("ENGINE_PUBLIC_KEY", None)
        env.pop("ENGINE_KEY_FINGERPRINT", None)
        completed = self._setup(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout + completed.stderr)
        self.assertIn("does not verify", completed.stderr)
        self.assertIn("259A55407DD6C00299E6607EFFDE55BE73A2D1ED", (ROOT / "scripts" / "setup.sh").read_text())
        self.assertFalse((root / "home" / "checkstead" / "dependency-check").exists())

    def test_setup_sh_installs_a_signed_engine(self) -> None:
        root = ROOT / "build" / "tests" / "setup-engine-signed"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        _engine_zip(archive, "Dependency-Check Core version 9.9.9")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        env = os.environ.copy()
        env["PIN"] = "9.9.9"
        env["python"] = "/usr/bin/python3"
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + "/usr/bin:/bin"
        completed = self._setup(root, env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Installed Dependency-Check 9.9.9", completed.stdout)
        binary = root / "home" / "checkstead" / "dependency-check" / "bin" / "dependency-check.sh"
        self.assertTrue(binary.is_file())
        reported = subprocess.run([str(binary), "--version"], check=True, capture_output=True, text=True)
        self.assertIn("9.9.9", reported.stdout)

    def _signed_engine_with_jar(self, root: Path) -> tuple[dict[str, str], Path]:
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "gnupg"
        public_key = root / "key.asc"
        fingerprint = _generate_key(home, public_key)
        archive = root / "dc.zip"
        _engine_zip(archive, "1.2.3")
        with zipfile.ZipFile(archive, "a") as bundle:
            bundle.writestr("dependency-check/lib/lib-1.0.jar", b"vulnerable 1.0")
        signature = root / "dc.zip.asc"
        _sign(home, archive, signature)
        version = root / "engine.version"
        version.write_text("1.2.3\n", encoding="utf-8")
        patched = root / "lib-1.1.jar"
        patched.write_bytes(b"patched 1.1")
        stub = root / "bin"
        stub.mkdir()
        _curl_stub(stub, archive, signature)
        # Jar URLs are served from the patched file.
        tool = stub / "curl"
        tool.write_text(
            tool.read_text(encoding="utf-8").replace(
                'case "$url" in\n', f'case "$url" in\n  *.jar) cp "{patched}" "$out" ;;\n'
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["ENGINE_VERSION_FILE"] = str(version)
        env["ENGINE_PUBLIC_KEY"] = str(public_key)
        env["ENGINE_KEY_FINGERPRINT"] = fingerprint
        env["PATH"] = str(stub) + os.pathsep + env.get("PATH", "")
        return env, patched

    def test_an_override_replaces_the_vulnerable_jar_under_its_name(self) -> None:
        root = ROOT / "build" / "tests" / "engine-override"
        env, patched = self._signed_engine_with_jar(root)
        overrides = root / "overrides.txt"
        digest = hashlib.sha256(patched.read_bytes()).hexdigest()
        overrides.write_text(f"# test\nlib-1.0.jar org/example/lib/1.1/lib-1.1.jar {digest}\n", encoding="utf-8")
        env["ENGINE_OVERRIDES"] = str(overrides)
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Replaced lib/lib-1.0.jar with lib-1.1.jar", completed.stdout)
        self.assertEqual((root / "dest" / "lib" / "lib-1.0.jar").read_bytes(), b"patched 1.1")

    def test_an_override_with_the_wrong_digest_is_refused(self) -> None:
        root = ROOT / "build" / "tests" / "engine-override-digest"
        env, _patched = self._signed_engine_with_jar(root)
        overrides = root / "overrides.txt"
        overrides.write_text(f"lib-1.0.jar org/example/lib/1.1/lib-1.1.jar {'0' * 64}\n", encoding="utf-8")
        env["ENGINE_OVERRIDES"] = str(overrides)
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn("Expected SHA-256", completed.stderr)
        self.assertFalse((root / "dest").exists())

    def test_a_stale_override_is_refused(self) -> None:
        root = ROOT / "build" / "tests" / "engine-override-stale"
        env, patched = self._signed_engine_with_jar(root)
        overrides = root / "overrides.txt"
        digest = hashlib.sha256(patched.read_bytes()).hexdigest()
        overrides.write_text(f"gone-2.0.jar org/example/gone/2.1/gone-2.1.jar {digest}\n", encoding="utf-8")
        env["ENGINE_OVERRIDES"] = str(overrides)
        completed = self._run(root, env)
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn("Remove its override", completed.stderr)

    def test_the_shipped_override_list_is_well_formed(self) -> None:
        lines = [
            line
            for line in (ROOT / "scripts" / "engine-overrides.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        self.assertTrue(lines)
        for line in lines:
            jar, path, digest = line.split()
            self.assertRegex(jar, r"^[A-Za-z0-9._-]+\.jar$")
            self.assertRegex(path, r"^[A-Za-z0-9._/-]+\.jar$")
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
