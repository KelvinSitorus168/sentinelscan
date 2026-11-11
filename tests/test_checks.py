import unittest

from sentinelscan.catalog import CATALOG, CHECK_LABELS, to_finding
from sentinelscan.checks import cookies, headers, platform
from sentinelscan.models import Hit, HttpResponse
from sentinelscan.scanner import grade_for, normalize


def resp(headers_list, url="https://example.com/", status=200):
    return HttpResponse(url=url, status=status, headers=headers_list)


def ids(hits):
    return [h.id for h in hits]


GOOD = resp([
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=(), microphone=()"),
    ("Server", "nginx"),
])


class HeaderChecks(unittest.TestCase):
    def test_good_site_has_no_header_hits(self):
        for check in (headers.check_hsts, headers.check_csp, headers.check_clickjacking,
                      headers.check_nosniff, headers.check_referrer, headers.check_permissions,
                      headers.check_info_leak):
            self.assertEqual(check(GOOD), [], check.__name__)

    def test_missing_everything(self):
        r = resp([])
        self.assertEqual(ids(headers.check_hsts(r)), ["hsts_missing"])
        self.assertEqual(ids(headers.check_csp(r)), ["csp_missing"])
        self.assertEqual(ids(headers.check_clickjacking(r)), ["clickjacking"])
        self.assertEqual(ids(headers.check_nosniff(r)), ["nosniff_missing"])
        self.assertEqual(ids(headers.check_referrer(r)), ["referrer_missing"])
        self.assertEqual(ids(headers.check_permissions(r)), ["permissions_missing"])

    def test_hsts_weak(self):
        r = resp([("Strict-Transport-Security", "max-age=300")])
        self.assertEqual(ids(headers.check_hsts(r)), ["hsts_short", "hsts_no_subdomains"])

    def test_csp_unsafe(self):
        r = resp([("Content-Security-Policy", "script-src 'self' 'unsafe-inline' 'unsafe-eval'")])
        self.assertEqual(ids(headers.check_csp(r)), ["csp_unsafe_inline", "csp_unsafe_eval"])

    def test_csp_unsafe_inline_ignored_with_nonce(self):
        r = resp([("Content-Security-Policy", "script-src 'nonce-x' 'unsafe-inline' 'strict-dynamic'")])
        self.assertEqual(headers.check_csp(r), [])

    def test_xfo_accepted(self):
        self.assertEqual(headers.check_clickjacking(resp([("X-Frame-Options", "sameorigin")])), [])

    def test_info_leak(self):
        r = resp([("Server", "Apache/2.4.41 (Ubuntu)"), ("X-Powered-By", "PHP/7.4.3")])
        self.assertEqual(ids(headers.check_info_leak(r)), ["server_version_leak", "powered_by_leak"])

    def test_referrer_unsafe(self):
        self.assertEqual(ids(headers.check_referrer(resp([("Referrer-Policy", "unsafe-url")]))),
                         ["referrer_unsafe"])

    def test_cors(self):
        origin = "https://probe.example"
        base = resp([])
        probe = resp([("Access-Control-Allow-Origin", origin),
                      ("Access-Control-Allow-Credentials", "true")])
        self.assertEqual(ids(headers.check_cors(base, probe, origin)), ["cors_reflect_credentials"])
        wildcard = resp([("Access-Control-Allow-Origin", "*")])
        self.assertEqual(ids(headers.check_cors(wildcard, None, origin)), ["cors_wildcard"])
        self.assertEqual(headers.check_cors(base, base, origin), [])


class CookieChecks(unittest.TestCase):
    def test_insecure_session_cookie(self):
        r = resp([("Set-Cookie", "sessionid=abc; Path=/")])
        hits = cookies.check_cookies([r])
        self.assertEqual(ids(hits), ["cookie_no_secure", "cookie_no_httponly", "cookie_no_samesite"])
        self.assertEqual(hits[1].severity, "medium")  # session-like name -> escalated
        self.assertNotIn("abc", " ".join(h.evidence for h in hits))  # value never leaked

    def test_secure_cookie(self):
        r = resp([("Set-Cookie", "sid=x; Secure; HttpOnly; SameSite=Lax")])
        self.assertEqual(cookies.check_cookies([r]), [])

    def test_samesite_none_without_secure(self):
        r = resp([("Set-Cookie", "pref=1; HttpOnly; SameSite=None")], url="http://example.com/")
        self.assertEqual(ids(cookies.check_cookies([r])), ["cookie_samesite_none_insecure"])

    def test_deleted_cookie_ignored(self):
        r = resp([("Set-Cookie", "old=; Max-Age=0")])
        self.assertEqual(cookies.check_cookies([r]), [])


class Misc(unittest.TestCase):
    def test_platform(self):
        r = resp([("Server", "Vercel"), ("X-Powered-By", "Next.js")])
        self.assertEqual(platform.detect([r]), ["vercel", "nextjs"])
        self.assertEqual(platform.detect([resp([("Server", "LiteSpeed")])]), ["litespeed"])

    def test_normalize(self):
        self.assertEqual(normalize("example.com"),
                         ("example.com", "https://example.com/", "http://example.com/"))
        self.assertEqual(normalize("http://localhost:8080/app")[1:],
                         ("https://localhost/app", "http://localhost:8080/app"))
        with self.assertRaises(ValueError):
            normalize("ftp://example.com")

    def test_grades(self):
        self.assertEqual(grade_for(100), "A+")
        self.assertEqual(grade_for(70), "C")
        self.assertEqual(grade_for(10), "F")

    def test_catalog_complete_and_bilingual(self):
        for key, entry in CATALOG.items():
            for field in ("title", "why", "fix"):
                self.assertTrue(entry[field]["en"] and entry[field]["id"], f"{key}.{field}")
            f = to_finding(Hit(key), "id")
            self.assertEqual(f.title, entry["title"]["id"])
        for key, entry in CHECK_LABELS.items():
            self.assertIn("id", entry, key)


if __name__ == "__main__":
    unittest.main()
