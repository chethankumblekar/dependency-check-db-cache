#!/usr/bin/env python3
"""Write a CycloneDX SBOM for this source tree.

The document names Checkstead, the installed certifi package, and the pinned
Dependency-Check release. It is not an image SBOM and it does not claim that
an image was signed.
"""

from __future__ import annotations

import json
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from checkstead import __version__  # noqa: E402
from checkstead.engine import pinned_engine  # noqa: E402


def certifi_version() -> str:
    try:
        return version("certifi")
    except PackageNotFoundError:
        return "uninstalled"


def build_sbom() -> dict:
    certifi = certifi_version()
    engine = pinned_engine()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "checkstead",
                "version": __version__,
            }
        },
        "components": [
            {
                "type": "library",
                "name": "certifi",
                "version": certifi,
                "purl": f"pkg:pypi/certifi@{certifi}",
            },
            {
                "type": "application",
                "name": "dependency-check",
                "version": engine,
                "purl": f"pkg:github/dependency-check/DependencyCheck@{engine}",
            },
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    payload = json.dumps(build_sbom(), indent=2) + "\n"
    if not args:
        sys.stdout.write(payload)
        return 0
    if len(args) != 1:
        print("usage: write-sbom.py [OUTPUT]", file=sys.stderr)
        return 1
    destination = Path(args[0])
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
