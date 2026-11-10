"""Test synthetic HTTP responses and a fixture-process deadline.

These checks exercise fixtures only. They do not execute a web page or verify
an isolation boundary for a browser.
"""
import subprocess
import sys
import unittest
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from threading import Thread
from time import perf_counter
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from backend.email_link_scans import skip_reason
from backend.tests.link_scan_fixture_server import BROWSER_BUDGET_SECONDS, FixtureHandler


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PageTags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class LinkFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.addClassCleanup(cls.server.server_close)
        Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.addClassCleanup(cls.server.shutdown)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    def get(self, path):
        return build_opener(ProxyHandler({}), NoRedirects()).open(self.base + path, timeout=4)

    def test_benign_and_fake_credential_form_responses(self):
        with self.get("/benign") as response:
            tags = PageTags()
            tags.feed(response.read().decode())
            self.assertFalse(any(tag == "form" for tag, _ in tags.tags))
            self.assertIsNone(response.headers.get("Content-Disposition"))
        with self.get("/fake-credential-form") as response:
            tags = PageTags()
            tags.feed(response.read().decode())
            self.assertIn(("form", {"method": "post", "action": "/never-submit"}), tags.tags)
            self.assertIn(("input", {"type": "password", "name": "password"}), tags.tags)

    def test_download_offer_is_headers_only(self):
        with self.get("/download") as response:
            self.assertTrue(response.headers["Content-Disposition"].startswith("attachment;"))
            self.assertEqual(response.headers["Content-Type"], "application/octet-stream")

    def test_internal_redirect_targets_are_rejected_before_following(self):
        for target in ("loopback", "lan", "metadata", "ipv6"):
            with self.subTest(target=target):
                with self.assertRaises(HTTPError) as error:
                    self.get("/redirect-" + target)
                with error.exception as response:
                    self.assertEqual(response.code, 302)
                    self.assertEqual(skip_reason(response.headers["Location"]), "Non-public network destination.")

    def test_slow_fixture_client_process_is_terminated_at_budget(self):
        request = ("import sys; from urllib.request import build_opener, ProxyHandler; "
                   "build_opener(ProxyHandler({})).open(sys.argv[1]).read()")
        started = perf_counter()
        with self.assertRaises(subprocess.TimeoutExpired):
            # subprocess.run kills and waits for this single test client when the deadline expires.
            subprocess.run([sys.executable, "-B", "-c", request, self.base + "/slow"],
                           check=True, timeout=BROWSER_BUDGET_SECONDS)
        elapsed = perf_counter() - started
        self.assertLess(elapsed, BROWSER_BUDGET_SECONDS + 5)
        print(f"  Controlled HTTP fixture client terminated at {elapsed:.3f} seconds")
