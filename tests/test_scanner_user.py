"""The scanner image can run as the host uid without becoming the default."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from unittest import TestCase

ROOT = Path(__file__).resolve().parents[1]


class ScannerUserTests(TestCase):
    def test_the_image_keeps_a_root_default_and_a_non_root_user(self) -> None:
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
