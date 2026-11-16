#!/usr/bin/env python3
"""Exercise a charge command against a local HTTP fixture, without merchant credentials."""

import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent
COMMANDS = {
    "node": ["node", "src/charge.js"],
    "python": [sys.executable, "src/charge.py"],
    "go": ["go", "run", "./cmd/charge"],
    "ruby": ["ruby", "lib/charge.rb"],
    "php": ["php", "src/charge.php"],
    "java": ["mvn", "-q", "compile", "exec:java", "-Dexec.mainClass=cash.fluxa.demo.ChargeDemo"],
    "rust": ["cargo", "run", "--quiet", "--bin", "charge"],
    "dotnet": ["dotnet", "run", "--project", "FluxaDemo", "--", "charge"],
}


def main():
    language = sys.argv[1]
    command = COMMANDS[language]
    env_path = ROOT / ".env"
    errors = []
    calls = []
    expected = {}
    order = {"id": "ord_fixture", "status": "pending", "amount": "9.99", "currency": "USD"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def handle_request(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            canonical = "\n".join([self.command, self.path, "", self.headers.get("X-Timestamp", ""), hashlib.sha256(raw).hexdigest()])
            signature = hmac.new(b"fixture-secret", canonical.encode(), hashlib.sha256).hexdigest()
            try:
                assert self.headers.get("X-Api-Key") == "pk_fixture", "API key"
                assert hmac.compare_digest(self.headers.get("X-Signature", ""), signature), "signed bytes differ from wire bytes"
                if self.command == "POST":
                    assert self.path == "/api/v1/charges", self.path
                    body = json.loads(raw)
                    assert body["amount"] == "9.99", "amount must remain a decimal string"
                    assert "settle_on_received" not in body, "ordinary charges must not opt in"
                    for key, value in expected.items():
                        assert body.get(key, "") == value, (key, body.get(key), value)
                    for key in ["network", "method", "presentation"]:
                        if not expected.get(key):
                            assert key not in body, ("empty optional field must be omitted", key)
                    response = {"order": order, "payment": {"id": "pay_fixture", "channel_code": "fixture"}, "instruction": {"type": "none"}, "idempotent": False}
                else:
                    assert self.path == "/api/v1/orders/ord_fixture", self.path
                    response = {"order": order, "payment": None, "settlements": []}
                calls.append(self.command)
                self.send_response(201 if self.command == "POST" else 200)
            except (AssertionError, ValueError) as error:
                errors.append(str(error))
                response = {"error": {"code": "fixture_failed", "message": str(error)}}
                self.send_response(400)
            data = json.dumps(response).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = handle_request
        do_POST = handle_request

    # Exclusive creation protects a developer's real .env; never read or replace credentials.
    with env_path.open("x") as file:
        file.write("FLUXA_KEY_ID=pk_fixture\nFLUXA_SECRET=fixture-secret\nFLUXA_CHANNEL=mock\n")
    server = None
    thread = None
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = {k: v for k, v in os.environ.items() if not k.startswith("FLUXA_") and k != "WEBHOOK_PORT"}
        env["FLUXA_BASE_URL"] = "http://127.0.0.1:{}".format(server.server_port)
        defaults = {"channel": "mock", "return_url": "https://example.com/pay/success", "cancel_url": "https://example.com/pay/cancel"}
        cases = [
            (defaults, {}),
            ({"channel": "fixture_fiat", "method": "wechat_pay", "return_url": "https://merchant.example/success", "cancel_url": "https://merchant.example/cancel"}, {"FLUXA_CHANNEL": "fixture_fiat", "FLUXA_METHOD": "wechat_pay", "FLUXA_RETURN_URL": "https://merchant.example/success", "FLUXA_CANCEL_URL": "https://merchant.example/cancel"}),
            ({**defaults, "channel": "", "network": "ethereum"}, {"FLUXA_CHANNEL": "", "FLUXA_NETWORK": "ethereum"}),
            ({**defaults, "channel": "stripe", "presentation": "embedded"}, {"FLUXA_CHANNEL": "stripe", "FLUXA_PRESENTATION": "embedded"}),
        ]
        for expected, overrides in cases:
            calls.clear()
            result = subprocess.run(command, cwd=ROOT / language, env={**env, **overrides}, capture_output=True, text=True, timeout=180)
            assert result.returncode == 0, result.stdout + result.stderr
            assert not errors, errors
            assert calls == ["POST", "GET"], calls
        print("{}: four charge wire-contract cases passed".format(language))
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        env_path.unlink()


if __name__ == "__main__":
    main()
