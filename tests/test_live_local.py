"""End-to-end test against a throwaway HTTP server on localhost."""

import http.server
import json
import threading
import unittest

from sentinelscan import cli
from sentinelscan.fetch import fetch_chain
from sentinelscan.scanner import scan


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path == "/old":
            self.send_response(301)
            self.send_header("Location", "/new")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Set-Cookie", "connect.sid=secret; Path=/")
        self.send_header("Set-Cookie", "theme=dark; Path=/; SameSite=Lax")
        self.end_headers()
        self.wfile.write(b"<h1>hi</h1>")

    def log_message(self, *args):
        pass


class LocalServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_redirect_chain_and_multiple_cookies(self):
        chain = fetch_chain(f"http://127.0.0.1:{self.port}/old")
        self.assertEqual([r.status for r in chain], [301, 200])
        self.assertEqual(len(chain[-1].get_all("set-cookie")), 2)

    def test_full_scan_http_only_site(self):
        result = scan(f"http://127.0.0.1:{self.port}/", lang="id", timeout=3)
        found = {f["id"] for f in result["findings"]}
        self.assertIn("https_unavailable", found)
        self.assertIn("no_https_redirect", found)
        self.assertIn("powered_by_leak", found)
        self.assertIn("cookie_no_httponly", found)
        self.assertNotIn("hsts_missing", found)  # HSTS only applies over HTTPS
        self.assertIn("express", result["platform"])
        self.assertEqual(result["grade"], "F")
        self.assertTrue(result["findings"][0]["title"])  # Indonesian text present
        json.dumps(result)  # serialisable

    def test_unreachable_is_not_graded(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        dead_port = server.server_address[1]
        server.server_close()  # port now refuses connections
        result = scan(f"http://127.0.0.1:{dead_port}/", timeout=2)
        self.assertFalse(result["reachable"])
        self.assertEqual(result["grade"], "N/A")
        self.assertEqual(result["findings"], [])
        self.assertEqual(cli.main([f"http://127.0.0.1:{dead_port}/", "-t", "2", "-o", "/dev/null"]), 3)

    def test_cli_fail_on(self):
        code = cli.main([f"http://127.0.0.1:{self.port}/", "--json", "--fail-on", "high", "-t", "3",
                         "-o", "/dev/null"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
