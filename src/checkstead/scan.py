from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.request import OpenerDirector

from checkstead.commit import lookup_commit
from checkstead.engine import NVD_NOTICE, pinned_engine
from checkstead.errors import ChecksteadError
from checkstead.report import write_report
from checkstead.roles import roles_from_paths
from checkstead.sarif import write_sarif
from checkstead.score import (
    COMMENT_NAME,
    POLICY_FAILURE,
    FindingLine,
    evaluate_report,
    partition_findings,
    policy_failures,
    render_pull_request_comment,
)
from checkstead.snapshot import resolve_snapshot, safe_extract
from checkstead.suppressions import (
    public_suppression_file,
    resolve_private_suppressions,
    seen_identifiers,
    suppression_report,
)

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
    home = source.get("HOME") or source.get("USERPROFILE") or str(Path.home())
    return Path(home) / "checkstead"


def engine_filenames() -> tuple[str, ...]:
    """dependency-check.bat is the Windows launcher. The shell script is the Unix one."""
    if os.name == "nt":
        return (
            "dependency-check.bat",
            "dependency-check.cmd",
            "dependency-check.sh",
            "dependency-check",
        )
    return (
        "dependency-check.sh",
        "dependency-check",
        "dependency-check.bat",
        "dependency-check.cmd",
    )


def resolve_engine(explicit: Path | None = None) -> Path:
    if explicit is not None:
        return explicit
    env = os.environ.get("CHECKSTEAD_ENGINE")
    if env:
        return Path(env)
    bundled = home_root() / "dependency-check" / "bin"
    for name in engine_filenames():
        candidate = bundled / name
        if candidate.is_file():
            return candidate
    for name in engine_filenames():
        found = shutil.which(name)
        if found:
            return Path(found)
    return Path("/opt/dependency-check/bin") / engine_filenames()[0]


def bundled_java(env: dict[str, str] | None = None) -> Path | None:
    directory = home_root(env) / "jdk" / "bin"
    for name in ("java", "java.exe"):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


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
WINDOWS_SETUP_COMMAND = (
    "irm https://raw.githubusercontent.com/chethankumblekar/dependency-check-db-cache/main/scripts/setup.ps1 | iex"
)


def setup_hint() -> str:
    if os.name == "nt":
        return WINDOWS_SETUP_COMMAND
    return SETUP_COMMAND


def command_environment(source: dict[str, str]) -> dict[str, str]:
    """Environment for dependency-check.sh. A failing java uses $HOME/checkstead/jdk."""
    env = scrub_environment(source)
    if java_ready(env):
        return env
    java = bundled_java(env)
    if java is None:
        raise ChecksteadError(
            "Java is not available. "
            f"Run {setup_hint()}"
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


def policy_lines(
    policy: str,
    threshold: float | None,
    fail_on_kev: bool,
    fail_unscored: bool,
    private_suppressions: Path | None,
) -> list[str]:
    threshold_text = "none" if threshold is None else f"{threshold:g}"
    private_text = str(private_suppressions) if private_suppressions else "none"
    return [
        f"score-policy: {policy}",
        f"threshold: {threshold_text}",
        f"fail-on-kev: {'true' if fail_on_kev else 'false'}",
        f"fail-unscored: {'true' if fail_unscored else 'false'}",
        f"private-suppressions: {private_text}",
    ]


def build_scan_command(
    engine: Path,
    data_dir: Path,
    scans: list[Path],
    project: str,
    out_dir: Path,
    env: dict[str, str] | None = None,
    suppressions: list[Path] | None = None,
) -> list[str]:
    """The Dependency-Check invocation. No API key and no update."""
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
    for suppression in suppressions or []:
        command.extend(["--suppression", str(suppression)])
    for scan in scans:
        command.extend(["--scan", str(scan)])
    return command


def _load_engine_payload(engine_report: Path) -> dict:
    if not engine_report.is_file():
        return {}
    try:
        loaded = json.loads(engine_report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ChecksteadError(
            f"Dependency-Check JSON report is not readable: {engine_report}"
        ) from exc
    if not isinstance(loaded, dict):
        raise ChecksteadError(f"Dependency-Check JSON report is not an object: {engine_report}")
    return loaded


def _write_scored_report(
    out_dir: Path,
    engine_version: str,
    snapshot_time: str,
    checksum: str,
    project: str | None,
    revision: str | None,
    author: str | None,
    author_email: str | None,
    score_policy: str,
    threshold: float | None,
    fail_on_kev: bool,
    fail_unscored: bool,
    private: Path | None,
    today: date,
    scans: list[Path],
    base_dir: Path | None = None,
    base_scans: list[Path] | None = None,
    pull_request: str | None = None,
) -> None:
    extra = policy_lines(score_policy, threshold, fail_on_kev, fail_unscored, private)
    payload = _load_engine_payload(out_dir / "dependency-check-report.json")
    scored = evaluate_report(
        payload,
        policy=score_policy,
        threshold=threshold,
        fail_on_kev=fail_on_kev,
        fail_unscored=fail_unscored,
        roles=roles_from_paths(scans),
    )
    introduced = scored.findings
    existing: list[FindingLine] = []
    failures = scored.failures
    if base_dir is not None:
        base_payload = _load_engine_payload(base_dir / "dependency-check-report.json")
        base_scored = evaluate_report(
            base_payload,
            policy=score_policy,
            threshold=threshold,
            fail_on_kev=fail_on_kev,
            fail_unscored=fail_unscored,
            roles=roles_from_paths(base_scans or []),
        )
        introduced, existing = partition_findings(scored.findings, base_scored.findings)
        failures = policy_failures(
            introduced,
            policy=score_policy,
            threshold=threshold,
            fail_on_kev=fail_on_kev,
            fail_unscored=fail_unscored,
        )
    write_sarif(out_dir, scored.findings, project)
    extra.extend(scored.lines)
    if private is not None:
        extra.extend(suppression_report(private, today, seen_identifiers(payload)))
    write_report(
        out_dir,
        engine_version,
        snapshot_time,
        checksum,
        project,
        revision,
        author,
        author_email,
        extra,
        pull_request,
    )
    if pull_request:
        (out_dir / COMMENT_NAME).write_text(
            render_pull_request_comment(
                pull_request,
                snapshot_time,
                introduced,
                existing,
                failures,
            ),
            encoding="utf-8",
        )
    if failures:
        raise ChecksteadError("\n".join(failures), exit_code=POLICY_FAILURE)


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
    score_policy: str = "prefer-newest",
    threshold: float | None = None,
    fail_on_kev: bool = False,
    fail_unscored: bool = False,
    private_suppressions: str = "",
    suppression_base: Path | None = None,
    base: list[Path] | None = None,
    pull_request: str | None = None,
) -> ScanResult:
    base_paths = list(base or [])
    for scan in scans:
        if not scan.exists():
            raise ChecksteadError(f"Scan path does not exist: {scan}")
    for path in base_paths:
        if not path.exists():
            raise ChecksteadError(f"Base path does not exist: {path}")
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
    private = resolve_private_suppressions(private_suppressions, suppression_base or Path.cwd())
    suppressions: list[Path] = []
    public = public_suppression_file()
    if public is not None:
        suppressions.append(public)
    if private is not None:
        suppressions.append(private)
    command = build_scan_command(
        engine_path,
        snapshot.data_dir,
        scans,
        project_name,
        out_dir,
        dict(os.environ),
        suppressions,
    )
    commands = [command]
    base_dir: Path | None = None
    if base_paths:
        base_dir = Path(tempfile.mkdtemp(prefix="checkstead-base-"))
        commands.append(
            build_scan_command(
                engine_path,
                snapshot.data_dir,
                base_paths,
                project_name,
                base_dir,
                dict(os.environ),
                suppressions,
            )
        )
    header = policy_lines(score_policy, threshold, fail_on_kev, fail_unscored, private)
    report_path = write_report(
        out_dir,
        snapshot.engine_version,
        snapshot.snapshot_time,
        snapshot.checksum,
        project_name,
        revision,
        author,
        author_email,
        header + ["findings: none"],
        pull_request,
    )
    (out_dir / "checkstead-command.txt").write_text(
        "\n\n".join("\n".join(item) for item in commands) + "\n",
        encoding="utf-8",
    )
    print(f"engine: {snapshot.engine_version}")
    print(f"snapshot: {snapshot.snapshot_time}")
    print(f"notice: {NVD_NOTICE}")
    try:
        if dry_run:
            write_sarif(out_dir, [], project_name)
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
        for item in commands:
            completed = subprocess.run(item, env=command_environment(dict(os.environ)), check=False)
            if completed.returncode != 0:
                raise ChecksteadError(
                    f"Dependency-Check exited {completed.returncode}.",
                    exit_code=completed.returncode,
                )
        _write_scored_report(
            out_dir,
            snapshot.engine_version,
            snapshot.snapshot_time,
            snapshot.checksum,
            project_name,
            revision,
            author,
            author_email,
            score_policy,
            threshold,
            fail_on_kev,
            fail_unscored,
            private,
            today,
            scans,
            base_dir,
            base_paths,
            pull_request,
        )
        return ScanResult(
            engine_version=snapshot.engine_version,
            snapshot_time=snapshot.snapshot_time,
            checksum=snapshot.checksum,
            command=tuple(command),
            report_path=report_path,
            dry_run=False,
        )
    finally:
        if base_dir is not None:
            shutil.rmtree(base_dir, ignore_errors=True)
