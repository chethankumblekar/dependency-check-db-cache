"""Extract a zip without letting a member write outside the destination."""

from __future__ import annotations

import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath


class ArchiveRejected(Exception):
    """The archive contains a member that is not safe to extract."""


def _parts(name: str) -> tuple[str, ...]:
    normalized = name.replace("\\", "/")
    if not normalized or "\x00" in normalized:
        raise ArchiveRejected("Snapshot archive has an empty or NUL path.")
    if normalized.startswith("/") or (len(normalized) >= 2 and normalized[1] == ":"):
        raise ArchiveRejected(f"Snapshot archive has an absolute path: {name}")
    parts = tuple(part for part in PurePosixPath(normalized).parts if part not in {"", "."})
    if not parts or any(part == ".." for part in parts):
        raise ArchiveRejected(f"Snapshot archive escapes its directory: {name}")
    return parts


def _destination(root: Path, name: str) -> Path:
    current = root
    parts = _parts(name)
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ArchiveRejected(f"Snapshot archive escapes its directory: {name}")
    target = current / parts[-1]
    if target.is_symlink():
        raise ArchiveRejected(f"Snapshot archive escapes its directory: {name}")
    resolved = target.resolve()
    if resolved != root and root not in resolved.parents:
        raise ArchiveRejected(f"Snapshot archive escapes its directory: {name}")
    return target


def _symlink_stays_inside(root: Path, link_path: Path, link_text: str, name: str) -> None:
    if "\x00" in link_text or not link_text:
        raise ArchiveRejected(f"Snapshot archive symlink is empty or unsafe: {name}")
    if link_text.startswith("/") or (len(link_text) >= 2 and link_text[1] == ":"):
        raise ArchiveRejected(f"Snapshot archive symlink escapes its directory: {name}")
    if ".." in PurePosixPath(link_text.replace("\\", "/")).parts:
        resolved = (link_path.parent / link_text).resolve()
        if resolved != root and root not in resolved.parents:
            raise ArchiveRejected(f"Snapshot archive symlink escapes its directory: {name}")
        return
    resolved = (link_path.parent / link_text).resolve()
    if resolved != root and root not in resolved.parents:
        raise ArchiveRejected(f"Snapshot archive symlink escapes its directory: {name}")


def safe_extract(zip_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise ArchiveRejected(f"Refusing to extract into a symlink: {dest}")
    root = dest.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            target = _destination(root, info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                link_text = archive.read(info).decode("utf-8")
                _symlink_stays_inside(root, target, link_text, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.symlink_to(link_text)
                continue
            if info.is_dir() or info.filename.replace("\\", "/").endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source, target.open("wb") as handle:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print("usage: archive.py ZIP DEST", file=sys.stderr)
        return 1
    try:
        safe_extract(Path(args[0]), Path(args[1]))
    except (ArchiveRejected, zipfile.BadZipFile, UnicodeDecodeError) as exc:
        print(f"Refusing archive: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
