"""Untrusted trees, engine timeouts, credential scrubbing, and the shared-cache lock."""

from __future__ import annotations

import multiprocessing
import os
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from unittest import TestCase, mock, skipIf

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead import scan as scan_module  # noqa: E402
from checkstead.errors import ChecksteadError  # noqa: E402
from checkstead.locking import exclusive_lock  # noqa: E402
from checkstead.scan import (  # noqa: E402
    UNTRUSTED_SOURCE_FLAGS,
    build_scan_command,
    run_engine,
    scan_timeout_seconds,
    scrub_environment,
    untrusted_source,
)


def _hold_lock(path: str, ready, release) -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from checkstead.locking import exclusive_lock as lock

    with lock(Path(path)):
        ready.set()
        release.wait(10)


class UntrustedSourceTests(TestCase):
    def command(self, untrusted: bool) -> list[str]:
        with mock.patch.object(scan_module, "yarn_runs", return_value=True):
            return build_scan_command(
                Path("/opt/dc/bin/dependency-check.sh"),
                Path("/tmp/data"),
                [Path("/work")],
                "demo",
                Path("/out"),
                {},
                [],
                untrusted,
            )

    def test_untrusted_turns_off_every_analyzer_that_runs_a_tool_in_the_tree(self) -> None:
        command = self.command(True)
        for flag in (
            "--disableYarnAudit",
            "--disablePnpmAudit",
            "--disableGolangMod",
            "--disableMixAudit",
            "--disableBundleAudit",
            "--disableSwiftPackageManagerAnalyzer",
        ):
            self.assertIn(flag, command)
        self.assertEqual(tuple(flag for flag in command if flag in UNTRUSTED_SOURCE_FLAGS), UNTRUSTED_SOURCE_FLAGS)
        self.assertIn("--noupdate", command)

    def test_trusted_keeps_the_existing_analyzers(self) -> None:
        command = self.command(False)
        for flag in UNTRUSTED_SOURCE_FLAGS:
            self.assertNotIn(flag, command)

    def test_environment_switch(self) -> None:
        self.assertTrue(untrusted_source({"CHECKSTEAD_UNTRUSTED_SOURCE": "1"}))
        self.assertFalse(untrusted_source({"CHECKSTEAD_UNTRUSTED_SOURCE": "0"}))
        self.assertFalse(untrusted_source({}))

    def test_the_github_app_scans_installed_repositories_as_untrusted(self) -> None:
        source = (ROOT / "src" / "checkstead" / "github_app.py").read_text(encoding="utf-8")
        self.assertIn("untrusted=True", source)

    def test_the_action_marks_pull_request_trees_untrusted(self) -> None:
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("CHECKSTEAD_UNTRUSTED_SOURCE=1", action)


class EnvironmentTests(TestCase):
    def test_credentials_do_not_reach_the_engine(self) -> None:
        cleaned = scrub_environment(
            {
                "PATH": "/usr/bin",
                "JAVA_HOME": "/opt/java",
                "JAVA_TOOL_OPTIONS": "-Xmx2g",
                "NVD_API_KEY": "x",
                "nvd_apikey": "x",
                "GITHUB_TOKEN": "x",
                "GH_TOKEN": "x",
                "CHECKSTEAD_GITHUB_CLIENT_SECRET": "x",
                "CHECKSTEAD_ENTRA_CLIENT_SECRET": "x",
                "CHECKSTEAD_SNAPSHOT_SIGNING_KEY": "x",
                "AWS_SECRET_ACCESS_KEY": "x",
                "DB_PASSWORD": "x",
                "AZURE_CREDENTIALS": "x",
            }
        )
        self.assertEqual(sorted(cleaned), ["JAVA_HOME", "JAVA_TOOL_OPTIONS", "PATH"])


class TimeoutTests(TestCase):
    def test_default_and_override(self) -> None:
        self.assertEqual(scan_timeout_seconds({}), 120 * 60)
        self.assertEqual(scan_timeout_seconds({"CHECKSTEAD_SCAN_TIMEOUT_MINUTES": "5"}), 300)
        self.assertEqual(scan_timeout_seconds({"CHECKSTEAD_SCAN_TIMEOUT_MINUTES": "0"}), 0)
        with self.assertRaises(ChecksteadError):
            scan_timeout_seconds({"CHECKSTEAD_SCAN_TIMEOUT_MINUTES": "ten"})

    @skipIf(os.name == "nt", "process groups are POSIX")
    def test_a_hung_engine_and_its_child_are_stopped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "child.pid"
            script = Path(tmp) / "engine.sh"
            script.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    sleep 60 &
                    echo $! > "{marker}"
                    wait
                    """
                ),
                encoding="utf-8",
            )
            script.chmod(0o755)
            started = time.monotonic()
            # Five seconds lets a loaded machine start the shell and its child
            # before the timeout; the test still checks both are stopped.
            with self.assertRaises(ChecksteadError) as caught:
                run_engine([str(script)], dict(os.environ), 5)
            self.assertLess(time.monotonic() - started, 40)
            self.assertTrue(marker.is_file(), "the fake engine did not start its child within 5 s")
            self.assertEqual(caught.exception.exit_code, 124)
            self.assertIn("CHECKSTEAD_SCAN_TIMEOUT_MINUTES", str(caught.exception))
            child = int(marker.read_text(encoding="utf-8").strip())
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    os.kill(child, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.1)
            else:
                self.fail("the engine's child process was left running")

    def test_a_finished_engine_returns_its_exit_code(self) -> None:
        self.assertEqual(run_engine([sys.executable, "-c", "raise SystemExit(3)"], dict(os.environ), 30), 3)


class LockTests(TestCase):
    def test_a_second_process_waits_for_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / ".lock"
            context = multiprocessing.get_context("spawn")
            ready = context.Event()
            release = context.Event()
            holder = context.Process(target=_hold_lock, args=(str(path), ready, release))
            holder.start()
            try:
                self.assertTrue(ready.wait(20))
                acquired = context.Event()

                def releaser() -> None:
                    time.sleep(0.5)
                    release.set()

                import threading

                threading.Thread(target=releaser, daemon=True).start()
                started = time.monotonic()
                with exclusive_lock(path):
                    acquired.set()
                self.assertGreaterEqual(time.monotonic() - started, 0.4)
            finally:
                release.set()
                holder.join(20)

    def test_snapshot_module_does_not_import_fcntl(self) -> None:
        source = (ROOT / "src" / "checkstead" / "snapshot.py").read_text(encoding="utf-8")
        self.assertNotIn("import fcntl", source)
