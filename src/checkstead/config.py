from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from checkstead.errors import ChecksteadError

DEFAULT_SNAPSHOT_URL = (
    "https://github.com/chethankumblekar/dependency-check-db-cache/releases/latest/download/manifest.json"
)
IMAGE_CONFIG = Path("/etc/checkstead/checkstead.yml")
RESERVED_KEYS = ("scorePolicy", "threshold", "privateSuppressions")


@dataclass(frozen=True)
class Config:
    snapshot_url: str
    reserved: dict[str, str]
    source: Path | None


def parse_config_text(text: str, source: Path | None = None) -> Config:
    """Read the flat config. Reserved keys are kept and not interpreted."""
    values: dict[str, str] = {}
    where = str(source) if source else "config"
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line[0].isspace():
            raise ChecksteadError(
                f"{where}:{lineno}: keep one key per line. Nested values are not used."
            )
        if ":" not in line:
            raise ChecksteadError(f"{where}:{lineno}: expected 'key: value'.")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if not key:
            raise ChecksteadError(f"{where}:{lineno}: missing key.")
        values[key] = value
    snapshot = values.pop("snapshot", "").strip()
    if not snapshot:
        raise ChecksteadError(f"{where}: set snapshot to a manifest URL.")
    reserved = {key: values.pop(key, "") for key in RESERVED_KEYS}
    reserved.update(values)
    return Config(snapshot_url=snapshot, reserved=reserved, source=source)


def default_config() -> Config:
    return Config(snapshot_url=DEFAULT_SNAPSHOT_URL, reserved={}, source=None)


def load_config(path: Path | None, cwd: Path | None = None) -> Config:
    """Resolve config from --config, ./checkstead.yml, the image file, then the default."""
    cwd = cwd or Path.cwd()
    candidates: list[Path] = []
    if path is not None:
        candidates.append(path)
    else:
        candidates.append(cwd / "checkstead.yml")
        candidates.append(IMAGE_CONFIG)
    for candidate in candidates:
        if candidate.is_file():
            return parse_config_text(candidate.read_text(encoding="utf-8"), candidate)
    if path is not None:
        raise ChecksteadError(f"Config file not found: {path}")
    return default_config()
