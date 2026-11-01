"""SSRF canary: a tiny HTTP server inside the crAPI network.

Every request is recorded in memory. ``GET /__requests`` returns them as JSON
so a regression test can prove that crAPI made a server-side request to an
address chosen by the attacker. Listens on 8080 and is never published.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = "QA-SSRF-CANARY-7f3c"
_lock = threading.Lock()
_requests: list[dict[str, str]] = []


class Handler(BaseHTTPRequestHandler):
    server_version = "qa-canary/1.0"

    def _reply(self, status: int, body: dict[str, object]) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self) -> None:
        if self.path == "/__health":
            self._reply(200, {"ok": True})
            return
        if self.path == "/__requests":
            with _lock:
                self._reply(200, {"requests": list(_requests)})
            return
        if self.path == "/__reset":
            with _lock:
                _requests.clear()
            self._reply(200, {"reset": True})
            return
        with _lock:
            _requests.append({"method": self.command, "path": self.path, "client": self.client_address[0]})
        self._reply(200, {"canary": MARKER, "path": self.path})

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle

    def log_message(self, format: str, *args: object) -> None:
        print(f"canary {self.client_address[0]} {format % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104 - container-internal only
