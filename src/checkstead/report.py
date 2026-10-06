from __future__ import annotations

from pathlib import Path

from checkstead.engine import NVD_NOTICE


def render_report(engine_version: str, snapshot_time: str, checksum: str) -> str:
    return (
        f"engine: {engine_version}\n"
        f"snapshot: {snapshot_time}\n"
        f"checksum: sha256:{checksum}\n"
        f"notice: {NVD_NOTICE}\n"
    )


def write_report(out_dir: Path, engine_version: str, snapshot_time: str, checksum: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "checkstead.txt"
    path.write_text(render_report(engine_version, snapshot_time, checksum), encoding="utf-8")
    return path
