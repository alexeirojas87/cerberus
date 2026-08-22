#!/usr/bin/env python3
"""
Cerberus R0 mock upstream server.

A lightweight HTTP server that records every request it receives and returns
a minimal valid LLM response. Used by the smoke test and proxy integration
tests to verify that the proxy forwards requests correctly.

Usage:
    python3 tools/mock-server.py [port] [--bind addr]

Environment:
    CERBERUS_MOCK_LOG  Path to log file (default: /tmp/cerberus-mock.log)

Output:
    Records receive to log file.
    Status endpoints: /__cerberus__/ready, /__cerberus__/health,
                      /__cerberus__/last, /__cerberus__/stats
"""

import json
import os
import signal
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Lock

log_lock = Lock()
request_count = 0
last_request = {}


class MockHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records reqs and returns LLM stubs."""

    def log_message(self, format, *args):
        if os.environ.get("LOG_REQUESTS") == "1":
            super().log_message(format, *args)

    def _record(self):
        global request_count, last_request
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        headers_dict = {k: v for k, v in self.headers.items()}
        last_request = {
            "method": self.command,
            "path": self.path,
            "headers": headers_dict,
            "body": body,
            "body_bytes": content_length,
        }

        with log_lock:
            request_count += 1

        log_file = os.environ.get("CERBERUS_MOCK_LOG", "/tmp/cerberus-mock.log")
        with log_lock:
            entry = json.dumps({
                "seq": request_count,
                "method": last_request["method"],
                "path": last_request["path"],
                "timestamp": time.time(),
            }) + "\n"
        try:
            with open(log_file, "a") as f:
                f.write(entry)
        except OSError:
            pass

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/__cerberus__/ready":
            self._send_json(200, {"ready": True})
        elif self.path == "/__cerberus__/health":
            self._send_json(200, {"ok": True})
        elif self.path == "/__cerberus__/last":
            with log_lock:
                self._send_json(200, last_request)
        elif self.path == "/__cerberus__/stats":
            with log_lock:
                self._send_json(200, {"total_requests": request_count})
        else:
            self._record()
            self._send_json(200, {
                "mock": True,
                "echo": {"method": self.command, "path": self.path, "body": last_request.get("body", "")},
            })

    def do_POST(self):
        self._record()
        self._send_json(200, {
            "mock": True,
            "echo": {"method": self.command, "path": self.path, "body": last_request.get("body", "")},
        })

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_POST()

    def do_PATCH(self):
        self.do_POST()


def run(port, bind):
    server = HTTPServer((bind, port), MockHandler)
    server.timeout = 0.5

    def _shutdown(sig, frame):
        print(f"[mock-server] Shutting down ({request_count} requests).", file=sys.stderr)
        server.shutdown()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    print(f"[mock-server] Listening on {bind}:{port}", file=sys.stderr)
    sys.stderr.flush()
    server.serve_forever()
    server.server_close()
    print(f"[mock-server] Stopped. Total requests: {request_count}.", file=sys.stderr)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
    bind = "127.0.0.1"
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--bind" and i + 1 < len(sys.argv):
            bind = sys.argv[i + 1]
            i += 2
        else:
            i += 1
    run(port, bind)
