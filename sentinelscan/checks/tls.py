"""TLS certificate and protocol-version checks."""

from __future__ import annotations

import socket
import ssl
import time

from ..models import Hit


def _name(rdns) -> str:
    for rdn in rdns or ():
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                return value
    return ""


def supports_version(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """True/False if the server accepts only this TLS version; None if we can't test it locally."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        # Our own OpenSSL build may refuse to speak old protocols at all.
        if "NO_PROTOCOLS_AVAILABLE" in str(exc).upper() or "no protocols available" in str(exc):
            return None
        return False
    except OSError:
        return False


def inspect(host: str, port: int = 443, timeout: float = 10.0) -> tuple[dict, list[Hit], dict[str, bool]]:
    """Return (info, hits, checks_ran) for the TLS endpoint."""
    info: dict = {"host": host, "port": port}
    hits: list[Hit] = []
    ran = {"certificate": False, "tls_versions": False}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                info["protocol"] = tls.version()
                info["cipher"] = (tls.cipher() or ("",))[0]
        ran["certificate"] = True
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        days_left = int((expires - time.time()) // 86400)
        info.update(
            subject=_name(cert.get("subject")),
            issuer=_name(cert.get("issuer")),
            not_after=cert.get("notAfter"),
            days_left=days_left,
        )
        # Thresholds are short on purpose: auto-renewed certs (Let's Encrypt,
        # Vercel, Cloudflare) routinely sit at ~30 days before renewal.
        if days_left < 7:
            hits.append(Hit("cert_expiring", f"Expires in {days_left} days ({cert['notAfter']})", "high"))
        elif days_left < 14:
            hits.append(Hit("cert_expiring", f"Expires in {days_left} days ({cert['notAfter']})"))
    except ssl.SSLCertVerificationError as exc:
        ran["certificate"] = True
        hits.append(Hit("cert_invalid", exc.verify_message or str(exc)))
    except (OSError, ssl.SSLError) as exc:
        info["error"] = str(exc)
        return info, hits, ran

    legacy = []
    tested = False
    for version, label in ((ssl.TLSVersion.TLSv1, "TLS 1.0"), (ssl.TLSVersion.TLSv1_1, "TLS 1.1")):
        result = supports_version(host, port, version, timeout)
        if result is not None:
            tested = True
        if result:
            legacy.append(label)
    info["legacy_versions_tested"] = tested
    if tested:
        ran["tls_versions"] = True
    if legacy:
        hits.append(Hit("legacy_tls", "Accepted: " + ", ".join(legacy)))
    return info, hits, ran
