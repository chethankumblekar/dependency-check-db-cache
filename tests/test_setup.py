"""The Mac setup command installs only what is missing and does not call NVD."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from contextlib import contextmanager
from datetime import date
from pathlib import Path
from unittest import TestCase, mock, skipUnless

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.errors import ChecksteadError  # noqa: E402
from checkstead.config import load_config  # noqa: E402
from checkstead.scan import SETUP_COMMAND, WINDOWS_SETUP_COMMAND, command_environment, resolve_engine, run_scan  # noqa: E402
from checkstead.suppressions import resolve_private_suppressions  # noqa: E402
from checkstead.ui import choose_scans_dir, prepare_scans_dir  # noqa: E402
from checkstead.snapshot import Snapshot  # noqa: E402

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


_UNAME_LINUX = """#!/bin/sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
  *) echo Linux ;;
esac
"""

# Writes junk to the -o target, so the download exists but is not the pinned file.
_CURL_TAMPERED = """#!/bin/sh
printf '%s\\n' "$*" >> "$SETUP_CURL_LOG"
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out=$2; shift; fi
  shift
done
[ -n "$out" ] && printf 'not the pinned archive' > "$out"
exit 0
"""


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

    def test_local_setup_leaves_an_existing_install(self) -> None:
        root = ROOT / "build" / "tests" / "setup-local"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        self._ready_home(home, bindir)
        env = self._env(home, bindir)
        env["CHECKSTEAD_LOCAL"] = "1"
        completed = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        for line in (
            "Python 3.11+ already present.",
            "java already runs.",
            "Dependency-Check 13.0.0 already present.",
            "checkstead already installed.",
            "Checkstead is ready.",
        ):
            self.assertIn(line, completed.stdout)
        self.assertNotIn("Open a new terminal", completed.stdout)

    @skipUnless(shutil.which("gpg"), "gpg is not installed")
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
        # No unpinned bootstrap script. A Python without ensurepip gets the
        # pinned, checksummed Python instead.
        self.assertNotIn("bootstrap.pypa.io", script)
        self.assertIn("import ensurepip", script)
        self.assertIn('python="$ROOT/python/bin/python3"', script)
        self.assertNotIn("services.nvd.nist.gov", script)
        self.assertNotIn("--updateonly", script)
        self.assertNotIn("nvdApiKey", script)
        self.assertNotIn("java_home", script)
        self.assertIn("--disableYarnAudit", script)
        self.assertIn("dependency-check.upstream.sh", script)

    def test_a_java_stub_is_replaced_by_the_home_jdk(self) -> None:
        root = ROOT / "build" / "tests" / "setup-java-stub"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        log = root / "curl.log"
        self._ready_home(home, bindir)
        _write(
            bindir / "java",
            "#!/bin/sh\necho 'Unable to locate a Java Runtime.' >&2\nexit 1\n",
        )
        _write(home / "checkstead" / "jdk" / "bin" / "java", "#!/bin/sh\nexit 0\n")
        env = self._env(home, bindir)
        env["SETUP_CURL_LOG"] = str(log)
        completed = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("JDK already installed.", completed.stdout)
        self.assertNotIn("java already runs.", completed.stdout)
        self.assertFalse(log.exists())
        profile = (home / ".zprofile").read_text(encoding="utf-8")
        jdk_at = profile.index('export JAVA_HOME="$HOME/checkstead/jdk"')
        path_at = profile.index('export PATH="$JAVA_HOME/bin:$PATH"')
        self.assertLess(jdk_at, path_at)
        wrapper = (home / "checkstead" / "bin" / "checkstead").read_text(encoding="utf-8")
        self.assertIn('export JAVA_HOME="$HOME/checkstead/jdk"', wrapper)
        self.assertIn('export PATH="$JAVA_HOME/bin:$PATH"', wrapper)
        stub = root / "stub-java"
        _write(stub / "java", "#!/bin/sh\nexit 1\n")
        forced = command_environment(
            {"HOME": str(home), "PATH": str(stub) + os.pathsep + "/usr/bin"}
        )
        self.assertEqual(forced["JAVA_HOME"], str(home / "checkstead" / "jdk"))
        self.assertEqual(forced["PATH"].split(os.pathsep)[0], str(home / "checkstead" / "jdk" / "bin"))

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

    def test_console_script_sets_java_home_before_dependency_check(self) -> None:
        root = ROOT / "build" / "tests" / "setup-launcher"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        jdk_java = home / "checkstead" / "jdk" / "bin" / "java"
        _write(jdk_java, "#!/bin/sh\nexit 0\n")
        stub = root / "stub"
        _write(stub / "java", "#!/bin/sh\necho 'Unable to locate a Java Runtime.' >&2\nexit 1\n")
        engine = root / "dependency-check.sh"
        _write(engine, "#!/bin/sh\nexit 0\n")
        project = root / "project"
        project.mkdir()
        (project / "README.txt").write_text("sample\n", encoding="utf-8")
        snapshot = Snapshot(
            engine_version="13.0.0",
            snapshot_time="2026-10-13T07:13:06Z",
            checksum="abc",
            database_path=root / "db.zip",
            data_dir=root / "data",
            manifest_path=root / "manifest.json",
        )
        captured: dict[str, object] = {}
        real_run = subprocess.run

        def fake_run(command, *args, **kwargs):
            program = command[0] if command else ""
            if str(program).endswith("/java") or str(program) == "java":
                return real_run(command, *args, **kwargs)
            captured["command"] = command
            captured["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(command, 0)

        def fake_engine(command, env, timeout):
            captured["command"] = command
            captured["env"] = env
            captured["timeout"] = timeout
            return 0

        with mock.patch.dict(
            os.environ,
            {"HOME": str(home), "PATH": str(stub), "NVD_API_KEY": "secret"},
        ):
            os.environ.pop("JAVA_HOME", None)
            os.environ.pop("CHECKSTEAD_ENGINE", None)
            with mock.patch("checkstead.scan.resolve_snapshot", return_value=snapshot), mock.patch(
                "checkstead.scan.safe_extract"
            ), mock.patch("checkstead.scan.subprocess.run", side_effect=fake_run), mock.patch(
                "checkstead.scan.run_engine", side_effect=fake_engine
            ):
                run_scan(
                    [project],
                    project="genesis",
                    config_snapshot_url="https://example.invalid/manifest.json",
                    out_dir=root / "out",
                    cache_dir=root / "cache",
                    today=date(2026, 10, 14),
                    dry_run=False,
                    engine=engine,
                )
        child = captured["env"]
        self.assertEqual(child["JAVA_HOME"], str(home / "checkstead" / "jdk"))
        self.assertEqual(child["PATH"].split(os.pathsep)[0], str(jdk_java.parent))
        self.assertNotIn("NVD_API_KEY", child)
        self.assertEqual(captured["timeout"], 120 * 60)
        command = captured["command"]
        self.assertIn("--noupdate", command)
        self.assertNotIn("nvdApiKey", command)

    def test_missing_jdk_names_the_setup_command(self) -> None:
        root = ROOT / "build" / "tests" / "setup-no-jdk"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        home.mkdir(parents=True)
        stub = root / "stub"
        _write(stub / "java", "#!/bin/sh\nexit 1\n")
        with self.assertRaises(ChecksteadError) as caught:
            command_environment({"HOME": str(home), "PATH": str(stub)})
        message = str(caught.exception)
        self.assertIn(SETUP_COMMAND, message)
        self.assertNotIn("exited 1", message)

    def test_linux_python_install_is_not_a_mac_build(self) -> None:
        root = ROOT / "build" / "tests" / "setup-linux-python"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        log = root / "curl.log"
        _write(bindir / "curl", "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SETUP_CURL_LOG\"\nexit 1\n")
        _write(bindir / "java", "#!/bin/sh\nexit 0\n")
        # The test describes a Linux x86_64 host whatever machine runs it.
        _write(bindir / "uname", _UNAME_LINUX)
        for name in ("python3", "python3.11", "python3.12", "python3.13", "python"):
            _write(bindir / name, "#!/bin/sh\nexit 1\n")
        env = self._env(home, bindir)
        env["SETUP_CURL_LOG"] = str(log)
        completed = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        recorded = log.read_text(encoding="utf-8")
        self.assertIn("x86_64-unknown-linux-gnu-install_only.tar.gz", recorded)
        self.assertIn("--proto =https", recorded)
        self.assertIn("--retry", recorded)
        self.assertNotIn("apple-darwin", recorded)
        self.assertNotIn("services.nvd.nist.gov", recorded)
        script = SETUP.read_text(encoding="utf-8")
        self.assertNotIn("needs macOS.", script)
        self.assertNotIn("sudo", script)
        windows = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")
        self.assertIn("x86_64-pc-windows-msvc", windows)
        self.assertIn("dependency-check.bat", windows)
        self.assertIn("SetEnvironmentVariable", windows)
        self.assertNotIn("sudo", windows)
        self.assertNotIn("services.nvd.nist.gov", windows)
        self.assertNotIn("nvdApiKey", windows)
        self.assertIn(WINDOWS_SETUP_COMMAND, (ROOT / "README.md").read_text(encoding="utf-8"))
        azure = (ROOT / "docs" / "azure.md").read_text(encoding="utf-8")
        self.assertIn("vmImage: ubuntu-latest", azure)
        self.assertIn("vmImage: windows-latest", azure)
        self.assertIn(SETUP_COMMAND, azure)
        self.assertIn(WINDOWS_SETUP_COMMAND, azure)
        self.assertIn("WEBSITES_PORT", azure)
        self.assertNotIn("services.nvd.nist.gov", azure.replace(
            "A scan does not use an NVD API key and does not call `services.nvd.nist.gov`.",
            "",
        ))

    def test_a_scan_from_another_directory_uses_the_project_file(self) -> None:
        root = ROOT / "build" / "tests" / "setup-any-directory"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        project = root / "project"
        elsewhere = root / "elsewhere"
        project.mkdir(parents=True)
        elsewhere.mkdir()
        (project / "empty.xml").write_text("<suppressions></suppressions>\n", encoding="utf-8")
        (project / "checkstead.yml").write_text(
            "scorePolicy: highest\nprivateSuppressions: empty.xml\n",
            encoding="utf-8",
        )
        config = load_config(None, elsewhere, [project])
        self.assertEqual(config.score_policy, "highest")
        self.assertEqual(config.source, project / "checkstead.yml")
        self.assertIsNone(resolve_private_suppressions("empty.xml", config.source.parent))
        explicit = load_config(project / "checkstead.yml", elsewhere, [root])
        self.assertEqual(explicit.source, project / "checkstead.yml")
        home = root / "home"
        packaged = root / "missing-packaged"
        created = prepare_scans_dir(choose_scans_dir(elsewhere, packaged, home / "checkstead"), explicit=False)
        self.assertEqual(created, home / "checkstead" / "scans")
        self.assertTrue(created.is_dir())
        with self.assertRaises(ChecksteadError):
            prepare_scans_dir(elsewhere / "absent", explicit=True)

    def test_engine_on_windows_is_the_batch_file_when_it_is_the_one_present(self) -> None:
        root = ROOT / "build" / "tests" / "setup-windows-engine"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bat = home / "checkstead" / "dependency-check" / "bin" / "dependency-check.bat"
        _write(bat, "@echo off\r\n")
        with mock_env(HOME=str(home)):
            self.assertEqual(resolve_engine(), bat)
        java = home / "checkstead" / "jdk" / "bin" / "java.exe"
        _write(java, "#!/bin/sh\nexit 0\n")
        forced = command_environment({"USERPROFILE": str(home), "PATH": str(root / "empty")})
        self.assertEqual(forced["JAVA_HOME"], str(home / "checkstead" / "jdk"))

    def test_engine_skips_yarn_audit_when_yarn_does_not_print_a_version(self) -> None:
        root = ROOT / "build" / "tests" / "setup-yarn-wrapper"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        self._ready_home(home, bindir)
        env = self._env(home, bindir)
        completed = subprocess.run(
            ["bash", str(SETUP)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        bindir_engine = home / "checkstead" / "dependency-check" / "bin"
        upstream = bindir_engine / "dependency-check.upstream.sh"
        wrapper = bindir_engine / "dependency-check.sh"
        log = root / "argv.txt"
        _write(
            upstream,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ENGINE_ARGV\"\necho 'Dependency-Check Core version 13.0.0'\n",
        )
        self.assertIn("checkstead setup: yarn audit", wrapper.read_text(encoding="utf-8"))

        def run_wrapper(path: str, *args: str) -> subprocess.CompletedProcess[str]:
            run_env = env.copy()
            run_env["PATH"] = path + os.pathsep + "/usr/bin:/bin"
            run_env["ENGINE_ARGV"] = str(log)
            return subprocess.run(
                [str(wrapper), *args],
                env=run_env,
                text=True,
                capture_output=True,
                check=False,
            )

        missing = root / "no-yarn"
        missing.mkdir()
        without = run_wrapper(str(missing), "--noupdate", "--scan", ".")
        self.assertEqual(without.returncode, 0, without.stdout + without.stderr)
        self.assertIn("--disableYarnAudit", log.read_text(encoding="utf-8"))

        yarn_bin = root / "with-yarn"
        _write(yarn_bin / "yarn", "#!/bin/sh\necho 1.22.22\n")
        with_yarn = run_wrapper(str(yarn_bin), "--noupdate", "--scan", ".")
        self.assertEqual(with_yarn.returncode, 0, with_yarn.stdout + with_yarn.stderr)
        self.assertNotIn("--disableYarnAudit", log.read_text(encoding="utf-8"))

        version = run_wrapper(str(missing), "--version")
        self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
        self.assertNotIn("--disableYarnAudit", log.read_text(encoding="utf-8"))
        self.assertIn("13.0.0", version.stdout)

    def test_readme_leads_with_the_setup_and_scan_commands(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        architecture = readme.index("## Architecture")
        self.assertLess(readme.index("## Setup"), architecture)
        self.assertLess(readme.index(SETUP_COMMAND), architecture)
        self.assertLess(readme.index("checkstead scan --scan . --project my-service"), architecture)
        self.assertLess(readme.index("checkstead-report/"), architecture)
        install = (
            "python -m pip install --upgrade --force-reinstall --no-cache-dir "
            "https://github.com/chethankumblekar/dependency-check-db-cache/archive/refs/heads/main.tar.gz"
        )
        self.assertLess(readme.index(install), architecture)

    def test_linux_macos_and_windows_installers_pin_the_engine_fingerprint(self) -> None:
        fingerprint = "259A55407DD6C00299E6607EFFDE55BE73A2D1ED"
        shell = SETUP.read_text(encoding="utf-8")
        windows = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")
        installer = (ROOT / "scripts" / "install-engine.sh").read_text(encoding="utf-8")
        for script in (shell, windows, installer):
            self.assertIn(fingerprint, script)
        shell_fn = shell.split("install_engine()", 1)[1].split("ensure_engine_wrapper()", 1)[0]
        self.assertLess(shell_fn.index("gpg --batch --verify"), shell_fn.index('"$python" "$archive_py"'))
        installer_fn = installer.split("gpg --batch --import", 1)[1]
        self.assertLess(installer_fn.index("gpg --batch --verify"), installer_fn.index('python3 "$ARCHIVE"'))
        engine = windows.split("function Install-Engine {", 1)[1].split("\nfunction ", 1)[0]
        self.assertLess(engine.index("gpg --batch --verify"), engine.index("dependency-check.bat"))
        self.assertNotIn("Expand-Archive", engine)
        self.assertIn("The release signature does not verify", engine)
        self.assertIn("gpg is required", shell)
        self.assertIn("gpg is required", windows)

    def test_a_download_that_is_not_the_pinned_digest_is_refused(self) -> None:
        root = ROOT / "build" / "tests" / "setup-tampered"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        log = root / "curl.log"
        _write(bindir / "curl", _CURL_TAMPERED)
        _write(bindir / "uname", _UNAME_LINUX)
        _write(bindir / "java", "#!/bin/sh\nexit 0\n")
        for name in ("python3", "python3.11", "python3.12", "python3.13", "python"):
            _write(bindir / name, "#!/bin/sh\nexit 1\n")
        env = self._env(home, bindir)
        env["SETUP_CURL_LOG"] = str(log)
        completed = subprocess.run(["bash", str(SETUP)], env=env, text=True, capture_output=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("Refusing the Python download. Expected SHA-256", completed.stderr)
        self.assertFalse((home / "checkstead" / "python").exists())

    def test_installers_pin_every_runtime_download(self) -> None:
        script = SETUP.read_text(encoding="utf-8")
        windows = (ROOT / "scripts" / "setup.ps1").read_text(encoding="utf-8")
        for text in (script, windows):
            self.assertNotIn("api.adoptium.net/v3/binary/latest", text)
            self.assertNotIn("get-pip.py", text)
            self.assertIn("jdk-21.0.12.1%2B1", text)
        # Python, the JDK, and each patched engine jar.
        self.assertEqual(script.count("verify_sha256 \""), 3)
        self.assertEqual(windows.count("Assert-Sha256 -Path"), 3)
        self.assertIn('Join-Path $env:SystemRoot "System32\\tar.exe"', windows)
        # $home is PowerShell's read-only $HOME; assigning it aborts the install.
        self.assertNotRegex(windows, r"(?im)^\s*\$home\s*=")
        # MSYS gpg (Git for Windows) reads a backslash GNUPGHOME as relative.
        self.assertIn("$env:GNUPGHOME = ConvertTo-GpgPath $gnupg", windows)

    def test_checkstead_ref_must_be_a_ref_name(self) -> None:
        root = ROOT / "build" / "tests" / "setup-ref"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        home = root / "home"
        bindir = root / "bin"
        _write(bindir / "java", "#!/bin/sh\nexit 0\n")
        env = self._env(home, bindir)
        env["CHECKSTEAD_REF"] = "../../evil"
        completed = subprocess.run(["bash", str(SETUP)], env=env, text=True, capture_output=True, check=False)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("CHECKSTEAD_REF is not a branch or tag name", completed.stderr)
