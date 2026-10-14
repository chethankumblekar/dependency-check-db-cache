"""The Mac setup command installs only what is missing and does not call NVD."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.scan import command_environment, resolve_engine  # noqa: E402

SETUP = ROOT / "scripts" / "setup.sh"


@contextmanager
def mock_env(**values: str):
    saved = os.environ.copy()
    os.environ.pop("CHECKSTEAD_ENGINE", None)
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class SetupTests(TestCase):
    def _env(self, home: Path, bindir: Path) -> dict[str, str]:
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["PATH"] = str(bindir) + os.pathsep + "/usr/bin:/bin"
        env.pop("CHECKSTEAD_ENGINE", None)
        env.pop("JAVA_HOME", None)
        return env

    def _ready_home(self, home: Path, bindir: Path) -> None:
        _write(bindir / "python3", "#!/bin/sh\nexit 0\n")
        _write(bindir / "java", "#!/bin/sh\nexit 0\n")
        _write(bindir / "curl", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SETUP_CURL_LOG\"\nexit 1\n")
        prefix = home / "checkstead"
        _write(
            prefix / "dependency-check" / "bin" / "dependency-check.sh",
            "#!/bin/sh\necho 'Dependency-Check Core version 13.0.0'\n",
        )
        _write(prefix / "venv" / "bin" / "checkstead", "#!/bin/sh\necho 13.0.0\n")

    def test_second_run_skips_what_is_already_present(self) -> None:
        root = ROOT / "build" / "tests" / "setup-second"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        log = root / "curl.log"
        self._ready_home(home, bindir)
        env = self._env(home, bindir)
        env["SETUP_CURL_LOG"] = str(log)
        first = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        for line in (
            "Python 3.11+ already present.",
            "java already runs.",
            "Dependency-Check 13.0.0 already present.",
            "checkstead already installed.",
            "PATH already includes $HOME/checkstead/bin.",
        ):
            self.assertIn(line, second.stdout)
        self.assertFalse(log.exists())
        profile = (home / ".zprofile").read_text(encoding="utf-8")
        self.assertEqual(profile.count("checkstead setup: user install on PATH"), 1)
        self.assertEqual((home / ".zshrc").read_text(encoding="utf-8").count(profile.strip().splitlines()[-1]), 1)

    def test_a_missing_engine_requests_the_pinned_zip_and_not_nvd(self) -> None:
        root = ROOT / "build" / "tests" / "setup-engine"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        log = root / "curl.log"
        self._ready_home(home, bindir)
        engine = home / "checkstead" / "dependency-check"
        subprocess.run(["rm", "-rf", str(engine)], check=True)
        env = self._env(home, bindir)
        env["SETUP_CURL_LOG"] = str(log)
        completed = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0)
        recorded = log.read_text(encoding="utf-8")
        self.assertIn("dependency-check-13.0.0-release.zip", recorded)
        self.assertNotIn("nvd", recorded.lower())
        self.assertNotIn("services.nvd.nist.gov", recorded)
        script = SETUP.read_text(encoding="utf-8")
        self.assertNotIn("sudo", script)
        self.assertIn("--without-pip", script)
        self.assertIn("https://bootstrap.pypa.io/get-pip.py", script)
        self.assertNotIn("services.nvd.nist.gov", script)
        self.assertNotIn("--updateonly", script)
        self.assertNotIn("nvdApiKey", script)

    def test_later_session_finds_the_home_engine_and_jdk(self) -> None:
        root = ROOT / "build" / "tests" / "setup-resolve"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        engine = home / "checkstead" / "dependency-check" / "bin" / "dependency-check.sh"
        _write(engine, "#!/bin/sh\n")
        java = home / "checkstead" / "jdk" / "bin" / "java"
        _write(java, "#!/bin/sh\nexit 0\n")
        other = root / "bin" / "dependency-check.sh"
        _write(other, "#!/bin/sh\n")
        with mock_env(HOME=str(home)):
            self.assertEqual(resolve_engine(), engine)
            os.environ["CHECKSTEAD_ENGINE"] = str(other)
            self.assertEqual(resolve_engine(), other)
        empty = root / "empty"
        empty.mkdir()
        fallback = command_environment({"HOME": str(home), "PATH": str(empty), "NVD_API_KEY": "secret"})
        self.assertEqual(fallback["JAVA_HOME"], str(home / "checkstead" / "jdk"))
        self.assertNotIn("NVD_API_KEY", fallback)
        self.assertIn(str(java.parent), fallback["PATH"].split(os.pathsep))
        present = root / "with-java"
        _write(present / "java", "#!/bin/sh\nexit 0\n")
        kept = command_environment({"HOME": str(home), "PATH": str(present)})
        self.assertNotIn("JAVA_HOME", kept)
