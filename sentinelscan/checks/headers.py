"""Security header checks. Each function takes an HttpResponse and returns Hits."""

from __future__ import annotations

import re

from ..models import Hit, HttpResponse

HSTS_MIN_AGE = 15552000  # 180 days


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return directives


def check_hsts(resp: HttpResponse) -> list[Hit]:
    value = resp.get("strict-transport-security")
    if not value:
        return [Hit("hsts_missing")]
    hits = []
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    age = int(match.group(1)) if match else 0
    if age < HSTS_MIN_AGE:
        hits.append(Hit("hsts_short", f"max-age={age}"))
    if "includesubdomains" not in value.lower():
        hits.append(Hit("hsts_no_subdomains", value))
    return hits


def check_csp(resp: HttpResponse) -> list[Hit]:
    value = resp.get("content-security-policy")
    if not value:
        if resp.get("content-security-policy-report-only"):
            return [Hit("csp_missing", "Only Content-Security-Policy-Report-Only is set (not enforced)")]
        return [Hit("csp_missing")]
    directives = parse_csp(value)
    scripts = directives.get("script-src", directives.get("default-src"))
    if scripts is None:
        return [Hit("csp_unsafe_inline", "No script-src or default-src: scripts are unrestricted")]
    hits = []
    # With a nonce/hash or 'strict-dynamic', browsers ignore 'unsafe-inline'.
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            or t == "'strict-dynamic'" for t in scripts)
    if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
        hits.append(Hit("csp_unsafe_inline", "script-src " + " ".join(scripts)))
    if "'unsafe-eval'" in scripts:
        hits.append(Hit("csp_unsafe_eval", "script-src " + " ".join(scripts)))
    return hits


def check_clickjacking(resp: HttpResponse) -> list[Hit]:
    csp = resp.get("content-security-policy")
    if csp and "frame-ancestors" in parse_csp(csp):
        return []
    xfo = (resp.get("x-frame-options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return []
    return [Hit("clickjacking", f"X-Frame-Options: {xfo}" if xfo else "")]


def check_nosniff(resp: HttpResponse) -> list[Hit]:
    value = (resp.get("x-content-type-options") or "").strip().lower()
    return [] if value == "nosniff" else [Hit("nosniff_missing", value)]


def check_referrer(resp: HttpResponse) -> list[Hit]:
    value = resp.get("referrer-policy")
    if not value:
        return [Hit("referrer_missing")]
    # The header may list fallbacks; the last supported value wins.
    last = value.split(",")[-1].strip().lower()
    return [Hit("referrer_unsafe", value)] if last == "unsafe-url" else []


def check_permissions(resp: HttpResponse) -> list[Hit]:
    return [] if resp.get("permissions-policy") else [Hit("permissions_missing")]


def check_info_leak(resp: HttpResponse) -> list[Hit]:
    hits = []
    server = resp.get("server")
    if server and re.search(r"\d+\.\d+", server):
        hits.append(Hit("server_version_leak", f"Server: {server}"))
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = resp.get(name)
        if value:
            hits.append(Hit("powered_by_leak", f"{name}: {value}"))
    return hits


def check_cors(resp: HttpResponse, probe: HttpResponse | None, probe_origin: str) -> list[Hit]:
    """resp: normal request. probe: same URL requested with a foreign Origin header."""
    for r in filter(None, (probe, resp)):
        acao = (r.get("access-control-allow-origin") or "").strip()
        creds = (r.get("access-control-allow-credentials") or "").strip().lower() == "true"
        if creds and acao in ("*", probe_origin, "null"):
            return [Hit("cors_reflect_credentials",
                        f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true")]
    if (resp.get("access-control-allow-origin") or "").strip() == "*":
        return [Hit("cors_wildcard", "Access-Control-Allow-Origin: *")]
    return []
