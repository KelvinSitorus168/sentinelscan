"""Orchestrates all checks for one target and produces a ScanResult dict."""

from __future__ import annotations

import ssl
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import __version__, fetch
from .catalog import label, to_finding
from .checks import cookies, headers, platform, tls
from .models import SEVERITY_ORDER, SEVERITY_PENALTY, Hit

PROBE_ORIGIN = "https://sentinelscan-cors-probe.example"


def normalize(target: str) -> tuple[str, str, str]:
    """Return (host, https_url, http_url) for a user-supplied target."""
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    parts = urlsplit(target)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Not a valid http(s) URL: {target}")
    host = parts.hostname
    path = parts.path or "/"
    https_port = parts.port if parts.scheme == "https" and parts.port else None
    http_port = parts.port if parts.scheme == "http" and parts.port else None
    https_netloc = host + (f":{https_port}" if https_port else "")
    http_netloc = host + (f":{http_port}" if http_port else "")
    https_url = urlunsplit(("https", https_netloc, path, parts.query, ""))
    http_url = urlunsplit(("http", http_netloc, path, parts.query, ""))
    return host, https_url, http_url


def grade_for(score: int) -> str:
    for threshold, grade in ((95, "A+"), (85, "A"), (75, "B"), (65, "C"), (50, "D")):
        if score >= threshold:
            return grade
    return "F"


def _fetch_tolerant(url: str, timeout: float, errors: list[str], label: str) -> list:
    """Fetch with normal TLS verification; on any TLS failure (bad certificate,
    TLS 1.0-only server, ...) retry without verification so headers can still
    be checked. The TLS module reports the TLS problem itself."""
    try:
        return fetch.fetch_chain(url, timeout=timeout)
    except ssl.SSLError:
        try:
            return fetch.fetch_chain(url, timeout=timeout, verify=False)
        except OSError as exc:  # ssl.SSLError is a subclass of OSError
            errors.append(f"{label}: {exc}")
    except OSError as exc:
        errors.append(f"{label}: {exc}")
    return []


def _unreachable(target: str, lang: str, errors: list[str]) -> dict:
    return {
        "tool": "sentinelscan", "version": __version__, "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "lang": lang,
        "final_url": None, "status": None, "redirect_chain": [], "platform": [], "tls": {},
        "reachable": False, "score": None, "grade": "N/A",
        "summary": {sev: 0 for sev in SEVERITY_ORDER}, "findings": [], "passed": [], "skipped": [],
        "errors": errors,
    }


def scan(target: str, lang: str = "en", timeout: float = 10.0) -> dict:
    host, https_url, http_url = normalize(target)
    hits: list[Hit] = []
    errors: list[str] = []
    checks: dict[str, list[Hit] | None] = {}  # None = could not run

    def record(name: str, result: list[Hit] | None) -> None:
        checks[name] = result
        if result:
            hits.extend(result)

    # 1. HTTPS (follow redirects). Retry without verification so a bad
    #    certificate doesn't stop us from checking headers; the TLS module
    #    reports the certificate problem itself.
    https_chain = _fetch_tolerant(https_url, timeout, errors, "HTTPS request failed")

    # 2. Plain HTTP should redirect to HTTPS. If that redirect lands on a
    #    broken HTTPS endpoint, the tolerant retry still records the hop.
    http_chain = _fetch_tolerant(http_url, timeout, errors,
                                 "HTTP request failed (port 80 may be closed, which is fine)")

    if not https_chain and not http_chain:
        # Nothing answered: DNS failure, firewall, offline site or no network
        # here. Don't grade a site we never saw.
        return _unreachable(target, lang, errors)

    record("https", [] if https_chain else [Hit("https_unavailable", https_url)])
    if http_chain:
        final_scheme = urlsplit(http_chain[-1].url).scheme
        first = http_chain[0]
        redirects_to_https = final_scheme == "https" or (
            first.is_redirect and (first.get("location") or "").lower().startswith("https://"))
        record("redirect", [] if redirects_to_https else
               [Hit("no_https_redirect", f"{http_url} → HTTP {first.status}")])
    else:
        checks["redirect"] = None

    # 3. Headers on the final page we can reach (HTTPS preferred).
    chain = https_chain or http_chain
    final = chain[-1] if chain else None
    if final is not None:
        if final.url.startswith("https://"):
            record("hsts", headers.check_hsts(final))
        else:
            checks["hsts"] = None
        record("csp", headers.check_csp(final))
        record("clickjacking", headers.check_clickjacking(final))
        record("nosniff", headers.check_nosniff(final))
        record("referrer", headers.check_referrer(final))
        record("permissions", headers.check_permissions(final))
        record("info_leak", headers.check_info_leak(final))
        probe = None
        try:
            probe = fetch.request(final.url, timeout=timeout, verify=False,
                                  extra_headers={"Origin": PROBE_ORIGIN})
        except (OSError, ssl.SSLError):
            pass
        record("cors", headers.check_cors(final, probe, PROBE_ORIGIN))
        record("cookies", cookies.check_cookies(https_chain + http_chain))

    # 4. TLS certificate + protocol versions.
    tls_info: dict = {}
    if https_chain or urlsplit(https_url).scheme == "https":
        port = urlsplit(https_url).port or 443
        tls_info, tls_hits, ran = tls.inspect(host, port, timeout)
        if "error" in tls_info and not https_chain:
            tls_info = {}
        cert_hits = [h for h in tls_hits if h.id in ("cert_invalid", "cert_expiring")]
        ver_hits = [h for h in tls_hits if h.id in ("legacy_tls", "no_modern_tls")]
        checks["certificate"] = cert_hits if ran["certificate"] else None
        checks["tls_versions"] = ver_hits if ran["tls_versions"] else None
        hits.extend(tls_hits)

    findings = [to_finding(h, lang) for h in hits]
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))
    score = max(0, 100 - sum(SEVERITY_PENALTY[f.severity] for f in findings))
    summary = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}

    passed = [label(name, lang) for name, res in checks.items() if res == []]
    skipped = [label(name, lang) for name, res in checks.items() if res is None]

    return {
        "tool": "sentinelscan",
        "version": __version__,
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "lang": lang,
        "final_url": final.url if final else None,
        "status": final.status if final else None,
        "redirect_chain": [f"{r.status} {r.url}" for r in chain],
        "platform": platform.detect(chain + http_chain),
        "tls": tls_info,
        "score": score,
        "reachable": True,
        "grade": grade_for(score),
        "summary": summary,
        "findings": [asdict(f) for f in findings],
        "passed": passed,
        "skipped": skipped,
        "errors": errors,
    }
