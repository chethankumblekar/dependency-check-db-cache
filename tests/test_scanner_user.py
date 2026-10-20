"""The scanner image can run as the host uid without becoming the default."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]


class ScannerUserTests(TestCase):
    def test_the_image_starts_as_root_only_to_drop_it(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        entry = (ROOT / "scripts" / "docker-entrypoint.sh").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("--uid 10001", dockerfile)
        self.assertIn("a+rX", dockerfile)
        self.assertNotRegex(dockerfile, r"(?m)^USER\s+")
        self.assertNotIn("privileged:", compose)
        self.assertNotRegex(dockerfile, r"(?im)^(?:USER|RUN).*(?:--privileged|privileged)")
        self.assertIn("/tmp/checkstead-", entry)
        self.assertIn('id -u', entry)
        self.assertIn("setpriv", entry)
        self.assertIn("--no-new-privs", entry)
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        azure = (ROOT / "integrations" / "azure-devops" / "task" / "index.js").read_text(encoding="utf-8")
        self.assertEqual(action.count('--user "$(id -u):$(id -g)"'), 2)
        self.assertIn("process.getuid", azure)
        self.assertIn('"--user"', azure)

    def test_a_non_root_uid_gets_a_writable_home(self) -> None:
        root = ROOT / "build" / "tests" / "scanner-user"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        root.mkdir(parents=True)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        locked = root / "locked"
        locked.mkdir()
        locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
        (bin_dir / "id").write_text("#!/bin/sh\necho 4242\n", encoding="utf-8")
        (bin_dir / "checkstead").write_text(
            "#!/bin/sh\nprintf 'HOME=%s\\nTMPDIR=%s\\n' \"$HOME\" \"${TMPDIR-}\"\n",
            encoding="utf-8",
        )
        os.chmod(bin_dir / "id", 0o755)
        os.chmod(bin_dir / "checkstead", 0o755)
        env = os.environ.copy()
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
        env["HOME"] = str(locked)
        env.pop("TMPDIR", None)
        completed = subprocess.run(
            ["bash", str(ROOT / "scripts" / "docker-entrypoint.sh"), "version"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("HOME=/tmp/checkstead-4242\n", completed.stdout)
        self.assertIn("TMPDIR=/tmp/checkstead-4242/tmp\n", completed.stdout)
        self.assertTrue((Path("/tmp/checkstead-4242") / ".cache" / "checkstead").is_dir())


class RootDropTests(TestCase):
    def _run(self, uid: str, owner: str, allow_root: bool = False) -> tuple[subprocess.CompletedProcess, Path]:
        root = ROOT / "build" / "tests" / "scanner-root-drop" / f"{uid}-{owner.replace(':', '_')}-{allow_root}"
        subprocess.run(["rm", "-rf", str(root)], check=True)
        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True)
        log = root / "calls.log"
        stubs = {
            "id": f"#!/bin/sh\necho {uid}\n",
            "stat": f"#!/bin/sh\necho {owner}\n",
            # Record the switch and stop: the re-executed entrypoint would run as the new user.
            "setpriv": f"#!/bin/sh\necho \"setpriv $*\" >> {log}\nexit 0\n",
            "checkstead": f"#!/bin/sh\necho \"checkstead $*\" >> {log}\n",
        }
        for name, body in stubs.items():
            (bin_dir / name).write_text(body, encoding="utf-8")
            os.chmod(bin_dir / name, 0o755)
        env = os.environ.copy()
        env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
        env.pop("CHECKSTEAD_ALLOW_ROOT", None)
        if allow_root:
            env["CHECKSTEAD_ALLOW_ROOT"] = "1"
        completed = subprocess.run(
            ["bash", str(ROOT / "scripts" / "docker-entrypoint.sh"), "version"],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return completed, log

    def test_root_drops_to_the_owner_of_the_working_directory(self) -> None:
        completed, log = self._run("0", "1000:1001")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = log.read_text(encoding="utf-8")
        self.assertIn("--reuid=1000 --regid=1001 --clear-groups", calls)
        self.assertIn("--inh-caps=-all --bounding-set=-all --no-new-privs", calls)
        self.assertNotIn("checkstead version", calls)

    def test_a_root_owned_directory_runs_as_the_image_user(self) -> None:
        _completed, log = self._run("0", "0:0")
        self.assertIn("--reuid=10001 --regid=10001", log.read_text(encoding="utf-8"))

    def test_root_is_kept_only_when_asked(self) -> None:
        completed, log = self._run("0", "1000:1000", allow_root=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        calls = log.read_text(encoding="utf-8")
        self.assertNotIn("setpriv", calls)
        self.assertIn("checkstead version", calls)

    def test_an_explicit_user_is_not_switched_again(self) -> None:
        _completed, log = self._run("4242", "1000:1000")
        calls = log.read_text(encoding="utf-8")
        self.assertNotIn("setpriv", calls)
        self.assertIn("checkstead version", calls)
