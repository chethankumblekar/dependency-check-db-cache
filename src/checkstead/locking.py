"""An exclusive lock on a file that works on Linux, macOS, and Windows.

The snapshot cache and the extracted database are shared by every scan on a
machine. Two processes must not download into, or extract over, the same
directory at once. ``fcntl`` does not exist on Windows, so importing it at
module level made the whole client fail to start there.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from checkstead.errors import ChecksteadError

if os.name == "nt":  # pragma: no cover - exercised on Windows only
    import msvcrt

    def _lock(handle) -> None:
        handle.seek(0)
        # LK_LOCK retries for about ten seconds and then raises. Keep waiting.
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                return
            except OSError:
                time.sleep(1)

    def _unlock(handle) -> None:
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(handle) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def _unlock(handle) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` for the duration of the block.

    The lock is released when the process exits, so a crashed scan does not
    leave the cache locked.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        handle = path.open("a+b")
    except OSError as exc:
        raise ChecksteadError(f"Could not open the lock file {path}: {exc}") from exc
    with handle:
        if os.name == "nt":  # pragma: no cover - Windows only
            # msvcrt locks a byte range, and the range must exist.
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
        _lock(handle)
        try:
            yield
        finally:
            _unlock(handle)
