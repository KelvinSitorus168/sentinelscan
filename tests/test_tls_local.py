"""Regression tests against a local HTTPS server with an untrusted certificate."""

import http.server
import os
import ssl
import threading
import unittest

from sentinelscan.checks import tls
from sentinelscan.scanner import scan

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class SelfSignedServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(FIXTURES, "selfsigned-cert.pem"),
                            os.path.join(FIXTURES, "selfsigned-key.pem"))
        cls.server.socket = ctx.wrap_socket(cls.server.socket, server_side=True)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_inspect_reports_untrusted_cert_without_crashing(self):
        info, hits, ran = tls.inspect("localhost", self.port, timeout=3)
        ids = [h.id for h in hits]
        self.assertIn("cert_invalid", ids)
        self.assertNotIn("no_modern_tls", ids)  # TLS 1.2+ works, only the cert is bad
        self.assertTrue(ran["certificate"])

    def test_full_scan_still_checks_headers(self):
        result = scan(f"https://localhost:{self.port}/", timeout=3)
        found = {f["id"] for f in result["findings"]}
        self.assertTrue(result["reachable"])
        self.assertIn("cert_invalid", found)
        self.assertNotIn("hsts_missing", found)  # headers were read despite the bad cert
        self.assertIn("csp_missing", found)

    def test_redirect_not_marked_untested_when_hsts_present(self):
        # Port 80 is closed on the test host, so no HTTP response is obtained.
        # Because the HTTPS endpoint sends HSTS, the redirect check must pass
        # rather than read as "not tested".
        result = scan(f"https://localhost:{self.port}/", timeout=3)
        self.assertNotIn("HTTP → HTTPS redirect", result["skipped"])
        self.assertIn("HTTP → HTTPS redirect", result["passed"])


if __name__ == "__main__":
    unittest.main()
