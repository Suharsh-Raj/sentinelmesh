"""Serve only synthetic LinkAgent fixtures. Run inside a disposable test guest."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import sleep


FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures" / "link_scan_responses.json").read_text(encoding="utf-8")
)
BROWSER_BUDGET_SECONDS = 12


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        response = FIXTURES.get(self.path)
        if response is None:
            self.send_error(404)
            return
        sleep(response.get("delay_seconds", 0))
        body = response["body"].encode("utf-8")
        self.send_response(response["status"])
        for name, value in response["headers"].items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # A timed-out fixture client has already exited.


if __name__ == "__main__":
    with ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler) as server:
        print(f"Fixture server: http://127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()
