"""DNS and email-authentication checks: SPF, DMARC, CAA, DNSSEC.

dnspython is an optional dependency. If it is not installed, `available()`
returns False and the scanner skips these checks with a note rather than
failing. The analysis is separated from resolution (via an injectable
`lookup` callable) so it can be unit-tested without network access.
"""

from __future__ import annotations

from ..models import Hit

# Which DNS record each check needs, for the "not tested" bookkeeping.
CHECKS = ("spf", "dmarc", "caa", "dnssec")


def available() -> bool:
    try:
        import dns.resolver  # noqa: F401
        return True
    except ImportError:
        return False


def _default_lookup(name: str, rdtype: str, timeout: float) -> list[str]:
    """Resolve a record to a list of plain strings. Empty list = no such record.
    Raises TimeoutError on a resolver timeout so the caller can mark the check
    as not tested rather than treating it as 'record absent'."""
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, rdtype, lifetime=timeout)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout as exc:
        raise TimeoutError(str(exc)) from exc

    out: list[str] = []
    for rdata in answer:
        if rdtype == "TXT":
            out.append(b"".join(rdata.strings).decode("utf-8", "replace"))
        elif rdtype == "MX":
            out.append(str(rdata.exchange).rstrip("."))
        elif rdtype == "CAA":
            out.append(f"{rdata.flags} {rdata.tag} {rdata.value}")
        else:
            out.append(str(rdata))
    return out


def _spf_all_token(record: str) -> str | None:
    for token in reversed(record.split()):
        bare = token.lower().lstrip("+-~?")
        if bare == "all":
            return token.lower()
    return None


def analyze(domain: str, lookup) -> tuple[dict, list[Hit], dict[str, bool]]:
    """lookup(name, rdtype) -> list[str]; may raise TimeoutError.
    Returns (info, hits, ran) where ran[check] is False if it couldn't run."""
    info: dict = {"domain": domain}
    hits: list[Hit] = []
    ran = {c: True for c in CHECKS}

    def safe(name: str, rdtype: str):
        try:
            return lookup(name, rdtype)
        except TimeoutError:
            return None  # signal "not tested"

    mx = safe(domain, "MX")
    has_mail = bool(mx)
    info["has_mx"] = has_mail

    # --- SPF (domain TXT with v=spf1) ---
    txt = safe(domain, "TXT")
    if txt is None:
        ran["spf"] = False
    else:
        spf_records = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf_records:
            hits.append(Hit("spf_missing", f"No v=spf1 TXT record on {domain}",
                            "medium" if has_mail else "low"))
        elif len(spf_records) > 1:
            hits.append(Hit("spf_multiple", f"{len(spf_records)} SPF records (RFC 7208 allows one)"))
        else:
            record = spf_records[0]
            info["spf"] = record
            tok = _spf_all_token(record)
            if tok in ("+all", "all"):
                hits.append(Hit("spf_all_pass", f"SPF ends with '{tok}'"))
            elif tok == "?all":
                hits.append(Hit("spf_neutral", "SPF ends with '?all' (neutral)"))

    # --- DMARC (_dmarc.domain TXT with v=DMARC1) ---
    dmarc_txt = safe(f"_dmarc.{domain}", "TXT")
    if dmarc_txt is None:
        ran["dmarc"] = False
    else:
        dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
        if not dmarc:
            hits.append(Hit("dmarc_missing", f"No DMARC record at _dmarc.{domain}",
                            "medium" if has_mail else "low"))
        else:
            record = dmarc[0]
            info["dmarc"] = record
            policy = ""
            for part in record.split(";"):
                key, _, value = part.strip().partition("=")
                if key.strip().lower() == "p":
                    policy = value.strip().lower()
            if policy == "none":
                hits.append(Hit("dmarc_policy_none", "DMARC policy is p=none (monitor only)"))

    # --- CAA (domain CAA) ---
    caa = safe(domain, "CAA")
    if caa is None:
        ran["caa"] = False
    elif not caa:
        hits.append(Hit("caa_missing", f"No CAA record on {domain}"))
    else:
        info["caa"] = caa

    # --- DNSSEC (heuristic: is a DNSKEY published at the apex?) ---
    dnskey = safe(domain, "DNSKEY")
    if dnskey is None:
        ran["dnssec"] = False
    elif not dnskey:
        hits.append(Hit("dnssec_missing", f"No DNSKEY published for {domain}"))
    else:
        info["dnssec"] = True

    return info, hits, ran


def inspect(domain: str, timeout: float = 5.0) -> tuple[dict, list[Hit], dict[str, bool]]:
    return analyze(domain, lambda name, rdtype: _default_lookup(name, rdtype, timeout))
