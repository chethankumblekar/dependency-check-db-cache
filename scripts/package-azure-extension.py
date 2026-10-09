#!/usr/bin/env python3
"""Stamp the Azure DevOps extension for one release tag and optionally pack a VSIX."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead.release import parse_tag, scanner_image, version_text

SOURCE = ROOT / "integrations" / "azure-devops"
IMAGE_LINE = re.compile(
    r'const DEFAULT_IMAGE =\n  "ghcr.io/chethankumblekar/dependency-check-db-cache/checkstead:[^"]+";'
)
TFX = "tfx-cli@0.24.2"


def stamp(dest: Path, tag: str, publisher: str | None = None) -> None:
    parts = parse_tag(tag)
    version = version_text(parts)
    image = scanner_image(parts)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(SOURCE, dest)

    manifest_path = dest / "vss-extension.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["version"] = version
    if publisher:
        manifest["publisher"] = publisher
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    task_path = dest / "task" / "task.json"
    task = json.loads(task_path.read_text(encoding="utf-8"))
    task["version"] = {"Major": parts[0], "Minor": parts[1], "Patch": parts[2]}
    for item in task["inputs"]:
        if item.get("name") == "image":
            item["defaultValue"] = image
    task_path.write_text(json.dumps(task, indent=2) + "\n", encoding="utf-8")

    index_path = dest / "task" / "index.js"
    text = index_path.read_text(encoding="utf-8")
    stamped, count = IMAGE_LINE.subn(f'const DEFAULT_IMAGE =\n  "{image}";', text, count=1)
    if count != 1:
        raise SystemExit("Could not stamp the scanner image in index.js.")
    index_path.write_text(stamped, encoding="utf-8")


def pack(dest: Path, vsix: Path) -> None:
    vsix.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "npx",
            "--yes",
            TFX,
            "extension",
            "create",
            "--manifest-globs",
            "vss-extension.json",
            "--output-path",
            str(vsix.resolve()),
        ],
        cwd=dest,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dest", type=Path, required=True)
    parser.add_argument("--publisher", default="")
    parser.add_argument("--vsix", type=Path)
    args = parser.parse_args(argv)
    stamp(args.dest, args.tag, args.publisher.strip() or None)
    if args.vsix is not None:
        pack(args.dest, args.vsix)
        print(args.vsix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
