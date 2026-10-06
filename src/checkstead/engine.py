from pathlib import Path

NVD_NOTICE = (
    "This product uses data from the NVD API but is not endorsed or certified by the NVD."
)


def pinned_engine() -> str:
    """Return the Dependency-Check release this build will run and accept."""
    path = Path(__file__).resolve().with_name("engine.version")
    version = path.read_text(encoding="utf-8").strip()
    if not version or any(character.isspace() for character in version):
        raise RuntimeError(f"Invalid engine pin in {path}")
    return version
