"""The last synced view of every repository source.

A sync asks each configured source for its repositories, branches, and
pipeline runs and keeps the answer on disk, so a page load never waits on a
Git host. A failed sync keeps the previous answer and records the error.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from checkstead.errors import ChecksteadError
from checkstead.sources.base import Source


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Inventory:
    def __init__(self, data_dir: Path, sources: list[Source]) -> None:
        self.directory = data_dir / "inventory"
        self.sources = sources
        self._lock = threading.Lock()
        self._syncing = threading.Event()
        self._stop = threading.Event()

    @property
    def syncing(self) -> bool:
        return self._syncing.is_set()

    def _path(self, kind: str) -> Path:
        return self.directory / f"{kind}.json"

    def _read(self, kind: str) -> dict | None:
        try:
            data = json.loads(self._path(kind).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _write(self, kind: str, data: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        target = self._path(kind)
        partial = target.with_suffix(".json.partial")
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        partial.replace(target)

    def sync(self) -> None:
        """Sync every configured source once. A second caller waits for the first."""
        with self._lock:
            self._syncing.set()
            try:
                for source in self.sources:
                    if source.configured():
                        self._sync_one(source)
            finally:
                self._syncing.clear()

    def _sync_one(self, source: Source) -> None:
        previous = self._read(source.kind) or {}
        record = {
            "kind": source.kind,
            "label": source.label,
            "syncedAt": previous.get("syncedAt"),
            "attemptedAt": _now(),
            "error": None,
            "repositories": previous.get("repositories", []),
            "runs": previous.get("runs", []),
        }
        try:
            repositories = source.list_repositories(include_branches=True)
            runs = source.list_runs()
        except ChecksteadError as exc:
            record["error"] = str(exc)
        except Exception as exc:  # A sync must never take the server down.
            print(f"checkstead: {source.kind} sync failed: {exc!r}", file=sys.stderr)
            record["error"] = f"The {source.label} sync failed unexpectedly."
        else:
            record["syncedAt"] = record["attemptedAt"]
            record["repositories"] = [repo.to_json() for repo in repositories]
            record["runs"] = [run.to_json() for run in runs]
        self._write(source.kind, record)

    def start_background(self) -> None:
        """Sync now and every CHECKSTEAD_SYNC_MINUTES (default 15; 0 turns it off)."""
        raw = os.environ.get("CHECKSTEAD_SYNC_MINUTES", "").strip()
        minutes = int(raw) if raw.isdigit() else 15
        if minutes == 0 or not any(source.configured() for source in self.sources):
            return

        def loop() -> None:
            while not self._stop.is_set():
                self.sync()
                self._stop.wait(minutes * 60)

        threading.Thread(target=loop, name="checkstead-sync", daemon=True).start()

    def sync_in_background(self) -> bool:
        """Start one sync unless one is running. True when this call started it."""
        if self._syncing.is_set():
            return False
        self._syncing.set()

        def run() -> None:
            try:
                self.sync()
            finally:
                self._syncing.clear()

        threading.Thread(target=run, name="checkstead-sync-now", daemon=True).start()
        return True

    def stop(self) -> None:
        self._stop.set()

    def view(self) -> list[dict]:
        found = []
        for source in self.sources:
            configured = source.configured()
            data = self._read(source.kind) if configured else None
            found.append(
                {
                    "kind": source.kind,
                    "label": source.label,
                    "configured": configured,
                    "syncedAt": (data or {}).get("syncedAt"),
                    "attemptedAt": (data or {}).get("attemptedAt"),
                    "error": (data or {}).get("error"),
                    "repositories": (data or {}).get("repositories", []),
                    "runs": (data or {}).get("runs", []),
                }
            )
        return found
