from __future__ import annotations

from pathlib import Path

from checkstead.engine import NVD_NOTICE


def render_report(
    engine_version: str,
    snapshot_time: str,
    checksum: str,
    project: str | None = None,
    revision: str | None = None,
    author: str | None = None,
    author_email: str | None = None,
) -> str:
    lines = [
        f"engine: {engine_version}",
        f"snapshot: {snapshot_time}",
        f"checksum: sha256:{checksum}",
    ]
    if project:
        lines.append(f"project: {project}")
    if revision:
        lines.append(f"revision: {revision}")
    if author:
        lines.append(f"author: {author}")
    if author_email:
        lines.append(f"author-email: {author_email}")
    lines.append(f"notice: {NVD_NOTICE}")
    return "\n".join(lines) + "\n"


def write_report(
    out_dir: Path,
    engine_version: str,
    snapshot_time: str,
    checksum: str,
    project: str | None = None,
    revision: str | None = None,
    author: str | None = None,
    author_email: str | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "checkstead.txt"
    path.write_text(
        render_report(
            engine_version,
            snapshot_time,
            checksum,
            project,
            revision,
            author,
            author_email,
        ),
        encoding="utf-8",
    )
    return path
