#!/usr/bin/env python3
"""A tiny local mock AI target for end-to-end testing of kirmizi-recon.

Serves:
  GET  /              -> a small HTML page (for http_fingerprint)
  GET  /robots.txt    -> a sample robots file
  POST /chat          -> an OpenAI-shaped JSON reply; simulates a guardrail
                         refusal for adversarial-looking prompts.

Run:   python tools/mock_target.py 8799
Then:  python -m kirmizi_recon --active --trust-local \
           -e http://127.0.0.1:8799/chat -d 127.0.0.1
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_MODEL = "mock-llm-1"
_REFUSAL_TRIGGERS = ("ignore previous", "system prompt", "developer message", "jailbreak")


class Handler(BaseHTTPRequestHandler):
    server_version = "MockAI/0.1"

    def log_message(self, *args):  # quiet
        pass

    def do_GET(self):
        if self.path.startswith("/robots.txt"):
            self._send(200, "text/plain", "User-agent: *\nDisallow: /admin\n")
            return
        self._send(
            200,
            "text/html",
            "<html><head><title>Mock AI Console</title></head>"
            "<body><h1>Mock AI</h1></body></html>",
            extra_headers={"X-Powered-By": "MockStack/2.0"},
        )

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            body = json.loads(raw)
            prompt = body["messages"][-1]["content"]
        except Exception:
            prompt = raw

        lowered = prompt.lower()
        if any(t in lowered for t in _REFUSAL_TRIGGERS):
            reply = "I can't help with that request."
        else:
            reply = (
                f"[{_MODEL}] I am a helpful assistant. I have access to a "
                "'search_docs' tool. How can I help?"
            )
        payload = {"model": _MODEL, "choices": [{"message": {"content": reply}}]}
        self._send(200, "application/json", json.dumps(payload))

    def _send(self, code, ctype, body, extra_headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8799
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"mock AI target on http://127.0.0.1:{port}  (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
