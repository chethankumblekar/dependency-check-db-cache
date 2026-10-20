#!/usr/bin/env python3
"""Load, stress, soak, and slow-client tests for a running Checkstead server.

Standard library only. It signs in with localhost sign-in, so point it at a
test server on loopback, never at production data.

  load    fixed concurrency for a duration
  stress  doubles concurrency each step until the error rate or p95 limit trips
  soak    fixed concurrency for a long duration, sampling the server's memory
          and open files when --pid is given
  slow    opens connections that send half a request and never finish, then
          checks they are dropped and that normal requests still succeed

Exit 0 when the run stays inside --max-error-rate and --max-p95-ms (and, for
soak, inside --max-rss-growth-mb). The summary is JSON on stdout.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

PATHS = ("/api/health", "/api/history", "/", "/api/session")


class Client:
    """Each worker thread keeps one connection open, the way a browser does.

    --new-connections opens one per request instead. On one machine that
    exhausts the client's ephemeral ports (TIME_WAIT) long before it says
    anything about the server.
    """

    def __init__(self, base: str, reuse: bool = True) -> None:
        parts = urlsplit(base)
        self.host = parts.hostname or "127.0.0.1"
        self.port = parts.port or 80
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.cookie = ""
        self.reuse = reuse
        self._local = threading.local()

    def _connection(self) -> http.client.HTTPConnection:
        connection = getattr(self._local, "connection", None)
        if connection is None or not self.reuse:
            connection = http.client.HTTPConnection(self.host, self.port, timeout=30)
            self._local.connection = connection
        return connection

    def request(self, method: str, path: str, body: bytes | None = None) -> int:
        headers = {"Origin": self.origin, "Accept-Encoding": "gzip"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        for attempt in (1, 2):
            connection = self._connection()
            try:
                connection.request(method, path, body=body, headers=headers)
                response = connection.getresponse()
                response.read()
            except (http.client.RemoteDisconnected, BrokenPipeError, ConnectionResetError):
                # The server closed an idle keep-alive connection. Reconnect once.
                connection.close()
                self._local.connection = None
                if attempt == 2:
                    raise
                continue
            cookie = response.getheader("Set-Cookie") or ""
            if cookie.startswith("checkstead_session="):
                self.cookie = cookie.split(";", 1)[0]
            if not self.reuse or response.getheader("Connection", "").lower() == "close":
                connection.close()
                self._local.connection = None
            return response.status
        raise AssertionError("unreachable")

    def sign_in(self) -> None:
        status = self.request("POST", "/api/session/local", b"{}")
        if status != 200 or not self.cookie:
            raise SystemExit(f"localhost sign-in failed with HTTP {status}; use a loopback test server")


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def run_fixed(client: Client, workers: int, seconds: float) -> dict:
    latencies: list[float] = []
    errors: list[str] = []
    lock = threading.Lock()
    stop = time.monotonic() + seconds

    def worker(offset: int) -> None:
        index = offset
        while time.monotonic() < stop:
            path = PATHS[index % len(PATHS)]
            index += 1
            started = time.perf_counter()
            try:
                status = client.request("GET", path)
                ok = status == 200
                detail = f"HTTP {status} {path}"
            except Exception as exc:  # noqa: BLE001 - every failure counts
                ok = False
                detail = f"{type(exc).__name__} {path}"
            elapsed = (time.perf_counter() - started) * 1000
            with lock:
                latencies.append(elapsed)
                if not ok:
                    errors.append(detail)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    began = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    duration = time.monotonic() - began
    total = len(latencies)
    return {
        "workers": workers,
        "seconds": round(duration, 1),
        "requests": total,
        "rps": round(total / duration, 1) if duration else 0,
        "errors": len(errors),
        "error_rate": round(len(errors) / total, 4) if total else 1.0,
        "p50_ms": round(statistics.median(latencies), 1) if latencies else 0,
        "p95_ms": round(_percentile(latencies, 0.95), 1),
        "p99_ms": round(_percentile(latencies, 0.99), 1),
        "max_ms": round(max(latencies), 1) if latencies else 0,
        "error_samples": sorted(set(errors))[:5],
    }


def process_stats(pid: int) -> dict:
    rss = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
    files = subprocess.run(["lsof", "-p", str(pid)], capture_output=True, text=True).stdout.count("\n")
    threads = subprocess.run(["ps", "-M", "-p", str(pid)] if sys.platform == "darwin" else ["ps", "-L", "-p", str(pid)],
                             capture_output=True, text=True).stdout.count("\n")
    return {"rss_mb": round(int(rss or 0) / 1024, 1), "open_files": max(files - 1, 0), "threads": max(threads - 1, 0)}


def slow_clients(client: Client, count: int, wait: float) -> dict:
    sockets = []
    for _ in range(count):
        sock = socket.create_connection((client.host, client.port), timeout=5)
        sock.sendall(b"GET /api/health HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        sockets.append(sock)
    during = run_fixed(client, 4, 3)
    time.sleep(wait)
    dropped = 0
    for sock in sockets:
        try:
            sock.settimeout(2)
            data = sock.recv(1)
            if data == b"":
                dropped += 1
        except (ConnectionResetError, BrokenPipeError):
            dropped += 1
        except socket.timeout:
            pass
        finally:
            sock.close()
    return {"slow_connections": count, "dropped_after_wait": dropped, "wait_s": wait, "normal_traffic_meanwhile": during}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["load", "stress", "soak", "slow"])
    parser.add_argument("--base", default="http://127.0.0.1:8765")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--max-workers", type=int, default=256)
    parser.add_argument("--max-error-rate", type=float, default=0.001)
    parser.add_argument("--max-p95-ms", type=float, default=1000)
    parser.add_argument("--pid", type=int, help="Server process id, for memory and file sampling.")
    parser.add_argument("--sample-every", type=float, default=60)
    parser.add_argument("--max-rss-growth-mb", type=float, default=50)
    parser.add_argument("--max-files-growth", type=int, default=100)
    parser.add_argument("--slow-count", type=int, default=50)
    parser.add_argument("--slow-wait", type=float, default=35)
    parser.add_argument("--new-connections", action="store_true", help="Open a connection per request.")
    args = parser.parse_args()

    client = Client(args.base, reuse=not args.new_connections)
    client.sign_in()
    ok = True
    if args.mode == "load":
        result = run_fixed(client, args.workers, args.seconds)
        ok = result["error_rate"] <= args.max_error_rate and result["p95_ms"] <= args.max_p95_ms
    elif args.mode == "stress":
        steps = []
        workers = args.workers
        breaking = None
        while workers <= args.max_workers:
            step = run_fixed(client, workers, args.seconds)
            steps.append(step)
            if step["error_rate"] > args.max_error_rate or step["p95_ms"] > args.max_p95_ms:
                breaking = workers
                break
            workers *= 2
        result = {"steps": steps, "first_failing_workers": breaking}
        recovery = run_fixed(client, args.workers, 5)
        result["recovery"] = recovery
        ok = recovery["error_rate"] <= args.max_error_rate
    elif args.mode == "soak":
        samples = []
        windows = []
        end = time.monotonic() + args.seconds
        if args.pid:
            samples.append(process_stats(args.pid))
        while time.monotonic() < end:
            span = min(args.sample_every, end - time.monotonic())
            windows.append(run_fixed(client, args.workers, span))
            if args.pid:
                samples.append(process_stats(args.pid))
        total = sum(window["requests"] for window in windows)
        errors = sum(window["errors"] for window in windows)
        result = {
            "windows": [{k: w[k] for k in ("requests", "rps", "errors", "p95_ms")} for w in windows],
            "requests": total,
            "errors": errors,
            "error_rate": round(errors / total, 5) if total else 1.0,
            "process": samples,
        }
        ok = result["error_rate"] <= args.max_error_rate and all(w["p95_ms"] <= args.max_p95_ms for w in windows)
        if len(samples) >= 3:
            # Growth after warm-up: the first window allocates caches and threads.
            growth = samples[-1]["rss_mb"] - samples[1]["rss_mb"]
            result["rss_growth_after_warmup_mb"] = round(growth, 1)
            files = samples[-1]["open_files"] - samples[1]["open_files"]
            result["open_files_growth_after_warmup"] = files
            # A descriptor leak grows without bound. Builds before 20 October 2026 held
            # one SQLite handle per session check until garbage collection.
            ok = ok and growth <= args.max_rss_growth_mb and files <= args.max_files_growth
    else:
        result = slow_clients(client, args.slow_count, args.slow_wait)
        ok = (
            result["dropped_after_wait"] == args.slow_count
            and result["normal_traffic_meanwhile"]["error_rate"] <= args.max_error_rate
        )
    result["mode"] = args.mode
    result["pass"] = ok
    print(json.dumps(result, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())
