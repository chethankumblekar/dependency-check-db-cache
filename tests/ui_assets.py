"""The web UI's source as the server ships it: the HTML shell plus its modules."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "checkstead" / "static"


def ui_source() -> str:
    parts = [(ROOT / "src" / "checkstead" / "ui_page.html").read_text(encoding="utf-8")]
    parts += [path.read_text(encoding="utf-8") for path in sorted(STATIC.rglob("*.js"))]
    parts.append((STATIC / "app.css").read_text(encoding="utf-8"))
    return "\n".join(parts)
