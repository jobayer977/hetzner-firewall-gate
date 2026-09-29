import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUNNER_IP = b"203.0.113.9"


class Firewall:
    def __init__(self, rules):
        self.rules = list(rules)
        self.lock = threading.Lock()
        self.calls = []
        self.hold_needle = None
        self.hold_seconds = 0.0

    def snapshot(self):
        with self.lock:
            return list(self.rules)

    def replace(self, rules):
        with self.lock:
            self.rules = list(rules)

    def descriptions(self):
        return [rule.get("description") or "" for rule in self.snapshot()]

    def should_hold(self, rules):
        if not self.hold_needle:
            return False
        return not any(self.hold_needle in (rule.get("description") or "") for rule in rules)


def build_handler(firewall):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, payload, raw=False):
            body = payload if raw else json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/ip":
                self._send(RUNNER_IP, raw=True)
                return
            rules = firewall.snapshot()
            firewall.calls.append(("GET", [r.get("description") for r in rules]))
            self._send({"firewall": {"rules": rules}})

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            rules = json.loads(self.rfile.read(length))["rules"]
            if firewall.should_hold(rules):
                firewall.hold_needle = None
                time.sleep(firewall.hold_seconds)
            firewall.replace(rules)
            firewall.calls.append(("SET", [r.get("description") for r in rules]))
            self._send({"actions": []})

    return Handler


def serve(firewall):
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler(firewall))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
