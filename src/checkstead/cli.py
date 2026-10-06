from __future__ import annotations

import argparse
import os
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from checkstead import __version__
from checkstead.engine import pinned_engine
from checkstead.errors import ChecksteadError
from checkstead.config import load_config
from checkstead.scan import default_cache_dir, run_scan
from checkstead.snapshot import utc_now, write_manifest


def _today() -> date:
    override = os.environ.get("CHECKSTEAD_TODAY")
    if override:
        try:
            return date.fromisoformat(override)
        except ValueError as exc:
            raise ChecksteadError(
                "CHECKSTEAD_TODAY must be YYYY-MM-DD."
            ) from exc
    return datetime.now(timezone.utc).date()


def _parse_time(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ChecksteadError("Manifest time must end with Z.")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ChecksteadError("Manifest time must look like 2026-10-06T01:00:00Z.") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _cmd_version(_args: argparse.Namespace) -> int:
    print(pinned_engine())
    return 0


def _cmd_ui(args: argparse.Namespace) -> int:
    from checkstead.ui import default_data_dir, default_scans_dir, serve

    scans = Path(args.scans) if args.scans else default_scans_dir()
    if not scans.is_dir():
        raise ChecksteadError(f"Scan directory not found: {scans}")
    data = Path(args.data) if args.data else default_data_dir()
    serve(scans, args.host, args.port, data)
    return 0


def _cmd_write_manifest(args: argparse.Namespace) -> int:
    moment = _parse_time(args.time) if args.time else utc_now()
    manifest = write_manifest(Path(args.zip), Path(args.out), moment)
    print(f"engine: {manifest['engineVersion']}")
    print(f"snapshot: {manifest['snapshotTime']}")
    print(f"checksum: sha256:{manifest['checksum']}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.scan:
        raise ChecksteadError("Pass at least one --scan path.")
    config = load_config(Path(args.config) if args.config else None, Path.cwd())
    project = args.project or None
    result = run_scan(
        [Path(scan) for scan in args.scan],
        project=project,
        config_snapshot_url=config.snapshot_url,
        out_dir=Path(args.out),
        cache_dir=Path(args.cache) if args.cache else default_cache_dir(),
        today=_today(),
        dry_run=args.dry_run,
        engine=Path(args.engine) if args.engine else None,
        revision=args.revision or None,
    )
    print(f"report: {result.report_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checkstead",
        description=(
            "Scan with the pinned OWASP Dependency-Check and a checksummed database "
            "snapshot. The scan does not use an NVD API key."
        ),
    )
    parser.add_argument("--version", action="version", version=f"checkstead {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a project with the pinned snapshot.")
    scan.add_argument("--scan", action="append", default=[], help="Path to scan. Repeatable.")
    scan.add_argument("--project", help="Name written into the Dependency-Check report.")
    scan.add_argument("--config", help="Path to checkstead.yml.")
    scan.add_argument("--out", default="checkstead-report", help="Report directory.")
    scan.add_argument("--cache", help="Snapshot cache. Defaults to ~/.cache/checkstead.")
    scan.add_argument("--engine", help="Path to dependency-check.sh. Defaults to CHECKSTEAD_ENGINE.")
    scan.add_argument("--revision", help="Commit or revision to record on the report, when you have one.")
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and verify the snapshot, write the report header, and do not start the engine.",
    )
    scan.set_defaults(func=_cmd_scan)

    ui = sub.add_parser("ui", help="Open the scan timeline in a browser.")
    ui.add_argument("--scans", help="Directory of scan reports. Defaults to ./ui/scans.")
    ui.add_argument("--data", help="Directory for users and sessions. Defaults to CHECKSTEAD_DATA or ~/.local/share/checkstead.")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8765)
    ui.set_defaults(func=_cmd_ui)

    manifest = sub.add_parser("write-manifest", help="Write a snapshot manifest for a database zip.")
    manifest.add_argument("--zip", required=True, help="Path to checkstead-db.zip.")
    manifest.add_argument("--out", required=True, help="Path to write manifest.json.")
    manifest.add_argument("--time", help="UTC snapshot time, YYYY-MM-DDTHH:MM:SSZ. Defaults to now.")
    manifest.set_defaults(func=_cmd_write_manifest)

    version = sub.add_parser("version", help="Print the pinned Dependency-Check release.")
    version.set_defaults(func=_cmd_version)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.func(args)
    except ChecksteadError as exc:
        print(f"checkstead: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
