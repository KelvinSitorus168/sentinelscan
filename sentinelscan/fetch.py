"""Minimal HTTP(S) client built on the standard library.

We use http.client directly (instead of urllib) so we can see every redirect
hop, keep repeated headers such as Set-Cookie, and control TLS verification.
"""

from __future__ import annotations

import http.client
import ssl
import time
from urllib.parse import urljoin, urlsplit

from . import __version__
from .models import HttpResponse

USER_AGENT = f"SentinelScan/{__version__} (passive security scanner)"
MAX_BODY = 256 * 1024


def permissive_context() -> ssl.SSLContext:
    """No verification and old protocols allowed, so we can still read the
    headers of a site whose certificate or TLS setup is broken. The TLS
    module reports those problems separately."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def request(url: str, timeout: float = 10.0, verify: bool = True,
            extra_headers: dict[str, str] | None = None) -> HttpResponse:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Unsupported URL: {url}")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    if parts.scheme == "https":
        ctx = ssl.create_default_context() if verify else permissive_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            parts.hostname, parts.port or 443, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)

    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    headers.update(extra_headers or {})
    try:
        start = time.monotonic()
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_BODY)  # bounded read
        elapsed = int((time.monotonic() - start) * 1000)
        return HttpResponse(url=url, status=resp.status, headers=list(resp.getheaders()),
                            elapsed_ms=elapsed, body=raw.decode("utf-8", "replace"))
    finally:
        conn.close()


def fetch_chain(url: str, timeout: float = 10.0, verify: bool = True,
                max_redirects: int = 5) -> list[HttpResponse]:
    """GET url and follow redirects, returning every hop (first to last)."""
    chain: list[HttpResponse] = []
    current = url
    for _ in range(max_redirects + 1):
        resp = request(current, timeout=timeout, verify=verify)
        chain.append(resp)
        if not resp.is_redirect:
            break
        nxt = urljoin(current, resp.get("location") or "")
        if urlsplit(nxt).scheme not in ("http", "https"):
            break
        current = nxt
    return chain
