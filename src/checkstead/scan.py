from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.request import OpenerDirector

from checkstead.commit import lookup_commit
from checkstead.engine import NVD_NOTICE, pinned_engine
from checkstead.errors import ChecksteadError
from checkstead.report import write_report
from checkstead.snapshot import resolve_snapshot, safe_extract

# Removed from the engine process so a key in the parent environment cannot be used.
_KEY_ENV_NAMES = ("NVD_API_KEY", "NVD_APIKEY")


@dataclass(frozen=True)
class ScanResult:
    engine_version: str
    snapshot_time: str
    checksum: str
    command: tuple[str, ...]
    report_path: Path
    dry_run: bool


def scrub_environment(source: dict[str, str]) -> dict[str, str]:
    """Copy the environment without an NVD API key."""
    blocked = {name.upper() for name in _KEY_ENV_NAMES}
    return {key: value for key, value in source.items() if key.upper() not in blocked}


def home_root(env: dict[str, str] | None = None) -> Path:
    source = env if env is not None else os.environ
    return Path(source.get("HOME") or str(Path.home())) / "checkstead"


def resolve_engine(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    env = os.environ.get("CHECKSTEAD_ENGINE")
    if env:
        return Path(env)
    bundled = home_root() / "dependency-check" / "bin" / "dependency-check.sh"
    if bundled.is_file():
        return bundled
    found = shutil.which("dependency-check.sh") or shutil.which("dependency-check")
    if found:
        return Path(found)
    return Path("/opt/dependency-check/bin/dependency-check.sh")


def java_ready(env: dict[str, str] | None = None) -> bool:
    """True when `java -version` exits 0. The macOS /usr/bin/java stub does not."""
    current = env if env is not None else dict(os.environ)
    java = shutil.which("java", path=current.get("PATH"))
    if not java:
        return False
    completed = subprocess.run(
        [java, "-version"],
        env=current,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    return completed.returncode == 0


SETUP_COMMAND = (
    "curl -fsSL https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.sh | bash"
)


def command_environment(source: dict[str, str]) -> dict[str, str]:
    """Environment for dependency-check.sh. A failing java uses $HOME/checkstead/jdk."""
    env = scrub_environment(source)
    if java_ready(env):
        return env
    java = home_root(env) / "jdk" / "bin" / "java"
    if not java.is_file():
        raise ChecksteadError(
            "Java is not available. "
            f"Run {SETUP_COMMAND}"
        )
    env["JAVA_HOME"] = str(java.parent.parent)
    env["PATH"] = str(java.parent) + os.pathsep + env.get("PATH", "")
    return env


def yarn_runs(env: dict[str, str] | None = None) -> bool:
    """True when `yarn --version` exits 0 and prints a version.

    Dependency-Check exits 14 after writing the reports when this check fails.
    """
    current = env if env is not None else dict(os.environ)
    yarn = shutil.which("yarn", path=current.get("PATH"))
    if not yarn or not os.access(yarn, os.X_OK):
        return False
    completed = subprocess.run(
        [yarn, "--version"],
        env=current,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        return False
    return bool(re.search(r"\d+\.\d+", completed.stdout or ""))


def build_scan_command(
    engine: Path,
    data_dir: Path,
    scans: list[Path],
    project: str,
    out_dir: Path,
    env: dict[str, str] | None = None,
) -> list[str]:
    """The Dependency-Check invocation. No API key, no update, no score policy."""
    if not scans:
        raise ChecksteadError("Pass at least one path to scan.")
    command = [
        str(engine),
        "--noupdate",
        "--disableVersionCheck",
        "--data",
        str(data_dir),
        "--project",
        project,
        "--out",
        str(out_dir),
        "--format",
        "HTML",
        "--format",
        "JSON",
        "--prettyPrint",
    ]
    if not yarn_runs(env):
        command.append("--disableYarnAudit")
    for scan in scans:
        command.extend(["--scan", str(scan)])
    return command


def default_cache_dir() -> Path:
    override = os.environ.get("CHECKSTEAD_CACHE")
    if override:
        return Path(override)
    return Path.home() / ".cache" / "checkstead"


def run_scan(
    scans: list[Path],
    *,
    project: str | None,
    config_snapshot_url: str,
    out_dir: Path,
    cache_dir: Path,
    today: date,
    dry_run: bool,
    engine: Path | None = None,
    opener: OpenerDirector | None = None,
    revision: str | None = None,
) -> ScanResult:
    for scan in scans:
        if not scan.exists():
            raise ChecksteadError(f"Scan path does not exist: {scan}")
    snapshot = resolve_snapshot(config_snapshot_url, cache_dir, today, opener)
    if snapshot.engine_version != pinned_engine():
        raise ChecksteadError(
            f"Resolved snapshot engine {snapshot.engine_version} does not match the pin."
        )
    engine_path = resolve_engine(engine)
    project_name = project or scans[0].name
    author = None
    author_email = None
    if revision:
        found = lookup_commit(revision, scans[0])
        if found:
            author, author_email = found
    out_dir.mkdir(parents=True, exist_ok=True)
    command = build_scan_command(
        engine_path,
        snapshot.data_dir,
        scans,
        project_name,
        out_dir,
        dict(os.environ),
    )
    report_path = write_report(
        out_dir,
        snapshot.engine_version,
        snapshot.snapshot_time,
        snapshot.checksum,
        project_name,
        revision,
        author,
        author_email,
    )
    (out_dir / "checkstead-command.txt").write_text("\n".join(command) + "\n", encoding="utf-8")
    print(f"engine: {snapshot.engine_version}")
    print(f"snapshot: {snapshot.snapshot_time}")
    print(f"notice: {NVD_NOTICE}")
    if dry_run:
        print("checkstead: dry run, Dependency-Check was not started.", flush=True)
        return ScanResult(
            engine_version=snapshot.engine_version,
            snapshot_time=snapshot.snapshot_time,
            checksum=snapshot.checksum,
            command=tuple(command),
            report_path=report_path,
            dry_run=True,
        )
    if not engine_path.is_file():
        raise ChecksteadError(
            "Dependency-Check is not installed at "
            f"{engine_path}. Install the pinned release or set CHECKSTEAD_ENGINE."
        )
    if not os.access(engine_path, os.X_OK):
        raise ChecksteadError(f"Dependency-Check is not executable: {engine_path}")
    safe_extract(snapshot.database_path, snapshot.data_dir)
    completed = subprocess.run(command, env=command_environment(dict(os.environ)), check=False)
    if completed.returncode != 0:
        raise ChecksteadError(
            f"Dependency-Check exited {completed.returncode}.",
            exit_code=completed.returncode,
        )
    return ScanResult(
        engine_version=snapshot.engine_version,
        snapshot_time=snapshot.snapshot_time,
        checksum=snapshot.checksum,
        command=tuple(command),
        report_path=report_path,
        dry_run=False,
    )
