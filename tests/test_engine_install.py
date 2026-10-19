"""The engine installer verifies a signature before it keeps a binary."""

from __future__ import annotations

import os
import stat
import subprocess
import zipfile
from pathlib import Path
from unittest import TestCase

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


class EngineInstallTests(TestCase):
    def _run(self, root: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
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
