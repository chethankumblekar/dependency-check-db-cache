"""Local page for the scan timeline. It only reads scan reports on disk."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from checkstead.history import history_payload, load_history

PAGE = Path(__file__).resolve().with_name("ui_page.html")


def default_scans_dir() -> Path:
    local = Path.cwd() / "ui" / "scans"
    if local.is_dir():
        return local
    return Path(__file__).resolve().parents[2] / "ui" / "scans"


def bind_server(scans_dir: Path, host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    scans_dir = scans_dir.resolve()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in {"/", "/index.html"}:
                body = PAGE.read_bytes()
                self._send(200, "text/html; charset=utf-8", body)
                return
            if path == "/api/history":
                payload = history_payload(load_history(scans_dir))
                body = json.dumps(payload).encode("utf-8")
                self._send(200, "application/json", body)
                return
            self._send(404, "text/plain; charset=utf-8", b"Not found\n")

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def serve(scans_dir: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = bind_server(scans_dir, host, port)
    shown_host, shown_port = server.server_address[:2]
    print(f"checkstead ui  http://{shown_host}:{shown_port}/")
    print(f"scans          {scans_dir.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
