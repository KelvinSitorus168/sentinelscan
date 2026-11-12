"""Orchestrates all checks for one target and produces a ScanResult dict."""

from __future__ import annotations

import ssl
from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from . import __version__, fetch
from .catalog import label, to_finding
from .checks import cookies, dns_email, headers, platform, tls
from .models import SEVERITY_ORDER, SEVERITY_PENALTY, Hit

PROBE_ORIGIN = "https://sentinelscan-cors-probe.example"


def check_securitytxt(base_url: str, timeout: float) -> list[Hit]:
    """A site is fine if /.well-known/security.txt (or /security.txt) returns a
    200 that looks like a real policy (has a Contact: line)."""
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(base_url)
    for path in ("/.well-known/security.txt", "/security.txt"):
        url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        try:
            resp = fetch.request(url, timeout=timeout, verify=False)
        except (OSError, ssl.SSLError):
            continue
        if resp.status == 200 and "contact:" in resp.body.lower():
            return []
    return [Hit("securitytxt_missing", "/.well-known/security.txt not found")]


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


def _fetch_tolerant(url: str, timeout: float, notes: list[dict], note_id: str) -> list:
    """Fetch with normal TLS verification; on any TLS failure (bad certificate,
    TLS 1.0-only server, ...) retry without verification so headers can still
    be checked. The TLS module reports the TLS problem itself. Failures are
    recorded as structured notes so the report can translate them."""
    try:
        return fetch.fetch_chain(url, timeout=timeout)
    except ssl.SSLError:
        try:
            return fetch.fetch_chain(url, timeout=timeout, verify=False)
        except OSError as exc:  # ssl.SSLError is a subclass of OSError
            notes.append({"id": note_id, "detail": str(exc)})
    except OSError as exc:
        notes.append({"id": note_id, "detail": str(exc)})
    return []


def _unreachable(target: str, lang: str, notes: list[dict]) -> dict:
    return {
        "tool": "sentinelscan", "version": __version__, "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "lang": lang,
        "final_url": None, "status": None, "redirect_chain": [], "platform": [], "tls": {}, "dns": {},
        "reachable": False, "score": None, "grade": "N/A",
        "summary": {sev: 0 for sev in SEVERITY_ORDER}, "findings": [], "passed": [], "skipped": [],
        "notes": notes,
    }


def scan(target: str, lang: str = "en", timeout: float = 10.0, check_dns: bool = True) -> dict:
    host, https_url, http_url = normalize(target)
    hits: list[Hit] = []
    notes: list[dict] = []
    checks: dict[str, list[Hit] | None] = {}  # None = could not run

    def record(name: str, result: list[Hit] | None) -> None:
        checks[name] = result
        if result:
            hits.extend(result)

    # 1. HTTPS (follow redirects). Retry without verification so a bad
    #    certificate doesn't stop us from checking headers; the TLS module
    #    reports the certificate problem itself.
    https_chain = _fetch_tolerant(https_url, timeout, notes, "https_failed")

    # 2. Plain HTTP should redirect to HTTPS. If that redirect lands on a
    #    broken HTTPS endpoint, the tolerant retry still records the hop.
    http_chain = _fetch_tolerant(http_url, timeout, notes, "http_port_closed")

    if not https_chain and not http_chain:
        # Nothing answered: DNS failure, firewall, offline site or no network
        # here. Don't grade a site we never saw.
        return _unreachable(target, lang, notes)

    record("https", [] if https_chain else [Hit("https_unavailable", https_url)])
    https_final = https_chain[-1] if https_chain else None
    if http_chain:
        final_scheme = urlsplit(http_chain[-1].url).scheme
        first = http_chain[0]
        redirects_to_https = final_scheme == "https" or (
            first.is_redirect and (first.get("location") or "").lower().startswith("https://"))
        record("redirect", [] if redirects_to_https else
               [Hit("no_https_redirect", f"{http_url} → HTTP {first.status}")])
    elif https_final is not None and https_final.get("strict-transport-security"):
        # Port 80 is closed/refused and HSTS is set: no plaintext is served and
        # browsers force HTTPS anyway. That's the strongest posture, so the
        # redirect check passes rather than reading as "not tested".
        record("redirect", [])
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
        record("securitytxt", check_securitytxt(final.url, timeout))

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

    # 5. DNS & email authentication (optional; needs dnspython).
    dns_info: dict = {}
    if check_dns and final is not None:
        dns_domain = host[4:] if host.startswith("www.") else host
        if dns_email.available():
            dns_info, dns_hits, dns_ran = dns_email.analyze(
                dns_domain, lambda n, r: dns_email._default_lookup(n, r, min(timeout, 5.0)))
            by_id = {h.id: h for h in dns_hits}
            checks["spf"] = ([h for h in dns_hits if h.id.startswith("spf")]
                             if dns_ran["spf"] else None)
            checks["dmarc"] = ([h for h in dns_hits if h.id.startswith("dmarc")]
                               if dns_ran["dmarc"] else None)
            checks["caa"] = ([by_id["caa_missing"]] if "caa_missing" in by_id
                             else ([] if dns_ran["caa"] else None))
            checks["dnssec"] = ([by_id["dnssec_missing"]] if "dnssec_missing" in by_id
                                else ([] if dns_ran["dnssec"] else None))
            hits.extend(dns_hits)
        else:
            for name in ("spf", "dmarc", "caa", "dnssec"):
                checks[name] = None
            notes.append({"id": "dnspython_missing", "detail": "pip install dnspython"})

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
        "dns": dns_info,
        "score": score,
        "reachable": True,
        "grade": grade_for(score),
        "summary": summary,
        "findings": [asdict(f) for f in findings],
        "passed": passed,
        "skipped": skipped,
        "notes": notes,
    }
