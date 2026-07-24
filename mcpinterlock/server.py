from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import DEMO, analyze


def make_handler(web_root: Path):
    class Handler(BaseHTTPRequestHandler):
        def _json(self, payload, status=HTTPStatus.OK):
            body = json.dumps(payload, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/api/demo":
                return self._json({"input": DEMO, "result": analyze(DEMO)})
            if self.path in ("/", "/index.html"):
                body = (web_root / "index.html").read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/analyze":
                    return self._json(analyze(payload))
                self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:
                self._json({"error": str(error)}, HTTPStatus.BAD_REQUEST)

        def log_message(self, *_):
            return

    return Handler


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), make_handler(Path(__file__).resolve().parent / "web"))
    print(f"mcpinterlock listening on http://{host}:{port}")
    server.serve_forever()
