"""The person who committed the revision a scan recorded.

The name comes from git. A scan with no revision, or a revision git cannot
resolve, does not invent one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def lookup_branch(start: Path) -> str | None:
    """The git branch of this tree. A detached HEAD or a tree without git records none."""
    directory = start if start.is_dir() else start.parent
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    name = (completed.stdout or "").strip()
    if not name or name == "HEAD" or any(char in name for char in "\r\n\x00"):
        return None
    return name[:200]


def lookup_commit(revision: str, start: Path) -> tuple[str, str] | None:
    if not revision or any(char in revision for char in "\r\n\x00"):
        return None
    directory = start if start.is_dir() else start.parent
    try:
        completed = subprocess.run(
            ["git", "-C", str(directory), "log", "-1", "--format=%an%x00%ae", revision],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    name, separator, email = completed.stdout.strip().partition("\x00")
    if not separator:
        return None
    name = " ".join(name.split())[:200]
    email = email.strip()[:200]
    if not name and not email:
        return None
    return name, email
