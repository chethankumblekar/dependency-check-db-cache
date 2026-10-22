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


def _cmd_doctor(_args: argparse.Namespace) -> int:
    """Print versions and configuration. Secret values are not printed."""
    engine = os.environ.get("CHECKSTEAD_ENGINE", "").strip()
    data = os.environ.get("CHECKSTEAD_DATA", "").strip()
    local = os.environ.get("CHECKSTEAD_LOCAL", "").strip()
    print(f"checkstead: {__version__}")
    print(f"engine-pin: {pinned_engine()}")
    print(f"engine-path: {engine or 'unset'}")
    if engine:
        print(f"engine-file: {'present' if Path(engine).is_file() else 'missing'}")
    else:
        print("engine-file: unset")
    print(f"cache: {default_cache_dir()}")
    print(f"data: {data or 'unset'}")
    if local == "1":
        local_mode = "any-peer"
    elif local == "0":
        local_mode = "disabled"
    else:
        local_mode = "loopback-peer"
    print(f"local-sign-in: {local or 'unset'} ({local_mode})")
    from checkstead.snapshot import max_snapshot_age_days
    from checkstead.snapshot_auth import load_trust, signature_required

    from checkstead.snapshot_auth import trust_source

    trust = load_trust()
    print(f"snapshot-trust: {trust_source()}")
    print(f"snapshot-trust-keys: {len(trust.keys)} ({', '.join(sorted(trust.keys)) or 'none'})")
    print(f"snapshot-signature: {'required' if signature_required(trust) else 'optional'}")
    print(f"snapshot-max-age-days: {max_snapshot_age_days()}")
    print(f"nvd-api-key: {'set' if os.environ.get('NVD_API_KEY') else 'unset'}")
    _doctor_sources()
    for name in (
        "CHECKSTEAD_GITHUB_CLIENT_SECRET",
        "CHECKSTEAD_ENTRA_CLIENT_SECRET",
        "CHECKSTEAD_AZURE_DEVOPS_CLIENT_SECRET",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    ):
        if os.environ.get(name):
            print(f"{name}: set")
    return 0


def _doctor_sources() -> None:
    """Repository sources and group access. Group ids are counted, not printed."""
    from checkstead.sources.azure_devops import AzureDevOpsSource

    azure = AzureDevOpsSource()
    state = "configured" if azure.configured() else "not configured"
    print(f"azure-devops-org: {azure.organization or 'unset'} ({state})")
    print(f"azure-devops-projects: {os.environ.get('CHECKSTEAD_AZURE_DEVOPS_PROJECTS', '').strip() or 'all'}")
    print(f"sync-minutes: {os.environ.get('CHECKSTEAD_SYNC_MINUTES', '').strip() or '15'}")
    for name in ("CHECKSTEAD_ENTRA_ALLOWED_GROUPS", "CHECKSTEAD_ENTRA_ADMIN_GROUPS"):
        groups = [item for item in os.environ.get(name, "").split(",") if item.strip()]
        print(f"{name.lower().replace('_', '-')}: {len(groups)} group(s)")


def _cmd_ui(args: argparse.Namespace) -> int:
    from checkstead.ui import default_data_dir, default_scans_dir, prepare_scans_dir, serve

    scans = prepare_scans_dir(
        Path(args.scans) if args.scans else default_scans_dir(),
        explicit=bool(args.scans),
    )
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


def _trust_entry(key_id: str, public_pem: str, not_after: str | None) -> str:
    import json

    entry: dict = {"id": key_id, "status": "current", "publicKeyPem": public_pem}
    if not_after:
        entry["notAfter"] = not_after
    return json.dumps(entry, indent=2)


def _cmd_snapshot_key(args: argparse.Namespace) -> int:
    """Create a signing key, or print the trust entry for an existing one.

    The private key never goes to stdout. The trust entry is the JSON object a
    maintainer adds to src/checkstead/snapshot_trust.json.
    """
    import re as _re

    from checkstead.snapshot_auth import KEY_ID, public_pem_for

    if not KEY_ID.fullmatch(args.id):
        raise ChecksteadError("--id must be letters, digits, dot, dash, or underscore.")
    if args.not_after and not _re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.not_after):
        raise ChecksteadError("--not-after must be YYYY-MM-DD.")
    if args.action == "generate":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if not args.out:
            raise ChecksteadError("generate needs --out for the private key file.")
        out = Path(args.out)
        pem = Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise ChecksteadError(f"Refusing to overwrite {out}.") from exc
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
        print(f"private-key: {out} (mode 0600). Store it as the CHECKSTEAD_SNAPSHOT_SIGNING_KEY secret.", file=sys.stderr)
        private = pem.decode("ascii")
    else:
        if args.key:
            private = Path(args.key).read_text(encoding="utf-8")
        else:
            private = os.environ.get("CHECKSTEAD_SNAPSHOT_SIGNING_KEY", "")
        if "PRIVATE KEY" not in private:
            raise ChecksteadError("Pass --key FILE or set CHECKSTEAD_SNAPSHOT_SIGNING_KEY.")
    print(_trust_entry(args.id, public_pem_for(private), args.not_after))
    return 0


def _cmd_seed_data(args: argparse.Namespace) -> int:
    """Extract the latest verified snapshot so the updater can update it in place.

    The manifest checksum and, when a key is pinned, the signature are checked
    exactly as a scan checks them. Any failure leaves --dest empty, and the
    updater then builds the database from nothing.
    """
    import shutil

    from checkstead.snapshot import resolve_snapshot, safe_extract

    dest = Path(args.dest)
    cache = Path(args.cache)
    try:
        snapshot = resolve_snapshot(args.url, cache, _today())
        if dest.exists():
            shutil.rmtree(dest)
        safe_extract(snapshot.database_path, dest)
    except Exception:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    print(f"seed: {snapshot.snapshot_time} checksum={snapshot.checksum} authenticity={snapshot.authenticity}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if not args.scan:
        raise ChecksteadError("Pass at least one --scan path.")
    scans = [Path(scan) for scan in args.scan]
    config = load_config(Path(args.config) if args.config else None, Path.cwd(), scans)
    project = args.project or None
    suppression_base = config.source.parent if config.source is not None else Path.cwd()
    result = run_scan(
        scans,
        project=project,
        config_snapshot_url=config.snapshot_url,
        out_dir=Path(args.out),
        cache_dir=Path(args.cache) if args.cache else default_cache_dir(),
        today=_today(),
        dry_run=args.dry_run,
        engine=Path(args.engine) if args.engine else None,
        revision=args.revision or None,
        score_policy=config.score_policy,
        threshold=config.threshold,
        fail_on_kev=config.fail_on_kev,
        fail_unscored=config.fail_unscored,
        private_suppressions=config.private_suppressions,
        suppression_base=suppression_base,
        base=[Path(path) for path in args.base],
        pull_request=args.pull_request or None,
        branch=args.branch or None,
        author=args.author or None,
        author_email=args.author_email or None,
        untrusted=True if args.untrusted_source else None,
    )
    for line in result.report_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("finding:"):
            print(line)
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
        "--base",
        action="append",
        default=[],
        help="Base tree to compare. Repeatable. Scanned with the same snapshot and --noupdate.",
    )
    scan.add_argument(
        "--pull-request",
        help="Pull request number recorded on the report, the comment, and the timeline.",
    )
    scan.add_argument(
        "--branch",
        help="Git branch recorded on the report. Defaults to the branch of the scanned tree.",
    )
    scan.add_argument("--author", help="Commit author recorded on the report.")
    scan.add_argument("--author-email", help="Commit author email recorded on the report.")
    scan.add_argument(
        "--untrusted-source",
        action="store_true",
        help=(
            "The scanned tree is not trusted, such as a fork pull request. Turns off analyzers "
            "that run yarn, pnpm, go, mix, bundle-audit, or swift inside it. "
            "Same as CHECKSTEAD_UNTRUSTED_SOURCE=1."
        ),
    )
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

    doctor = sub.add_parser("doctor", help="Print versions and configuration without secrets.")
    doctor.set_defaults(func=_cmd_doctor)

    key = sub.add_parser(
        "snapshot-key",
        help="Create a snapshot signing key, or print the trust entry to pin for one.",
    )
    key.add_argument("action", choices=["generate", "public"])
    key.add_argument("--id", required=True, help="Key id, for example checkstead-2026-10.")
    key.add_argument("--out", help="generate: where to write the new private key (mode 0600).")
    key.add_argument("--key", help="public: private key file. Defaults to CHECKSTEAD_SNAPSHOT_SIGNING_KEY.")
    key.add_argument("--not-after", help="Last UTC day this key may sign, YYYY-MM-DD.")
    key.set_defaults(func=_cmd_snapshot_key)

    seed = sub.add_parser(
        "seed-data",
        help="Extract the latest verified snapshot for an incremental update. Used by the updater.",
    )
    seed.add_argument("--url", required=True, help="Snapshot manifest URL.")
    seed.add_argument("--dest", required=True, help="Directory to extract the database into.")
    seed.add_argument("--cache", required=True, help="Download cache for the seed.")
    seed.set_defaults(func=_cmd_seed_data)
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
