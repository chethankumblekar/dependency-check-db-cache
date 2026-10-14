from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from checkstead.errors import ChecksteadError
from checkstead.score import POLICIES

DEFAULT_SNAPSHOT_URL = (
    "https://github.com/chethankumblekar/dependency-check-db-cache/releases/latest/download/manifest.json"
)
IMAGE_CONFIG = Path("/etc/checkstead/checkstead.yml")
DEFAULT_POLICY = "prefer-newest"


@dataclass(frozen=True)
class Config:
    snapshot_url: str
    score_policy: str
    threshold: float | None
    fail_on_kev: bool
    fail_unscored: bool
    private_suppressions: str
    source: Path | None


def _bool(value: str, key: str, where: str) -> bool:
    text = value.strip().lower()
    if text in {"", "false", "no"}:
        return False
    if text in {"true", "yes"}:
        return True
    raise ChecksteadError(f"{where}: {key} must be true or false.")


def _threshold(value: str, where: str) -> float | None:
    text = value.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError as exc:
        raise ChecksteadError(f"{where}: threshold must be a number.") from exc


def _policy(value: str, where: str) -> str:
    text = value.strip() or DEFAULT_POLICY
    if text not in POLICIES:
        raise ChecksteadError(
            f"{where}: scorePolicy must be prefer-newest or highest."
        )
    return text


def parse_config_text(text: str, source: Path | None = None) -> Config:
    """Read the flat config. One key per line."""
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
    policy = _policy(values.pop("scorePolicy", ""), where)
    threshold = _threshold(values.pop("threshold", ""), where)
    fail_on_kev = _bool(values.pop("failOnKev", ""), "failOnKev", where)
    fail_unscored = _bool(values.pop("failUnscored", ""), "failUnscored", where)
    private_suppressions = values.pop("privateSuppressions", "").strip()
    return Config(
        snapshot_url=snapshot,
        score_policy=policy,
        threshold=threshold,
        fail_on_kev=fail_on_kev,
        fail_unscored=fail_unscored,
        private_suppressions=private_suppressions,
        source=source,
    )


def default_config() -> Config:
    return Config(
        snapshot_url=DEFAULT_SNAPSHOT_URL,
        score_policy=DEFAULT_POLICY,
        threshold=None,
        fail_on_kev=False,
        fail_unscored=False,
        private_suppressions="",
        source=None,
    )


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
