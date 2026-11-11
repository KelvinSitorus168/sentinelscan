"""Cookie attribute checks. Cookie values are never stored or printed."""

from __future__ import annotations

import re

from ..models import Hit, HttpResponse

SESSION_HINT = re.compile(
    r"(sess|sid|token|auth|jwt|login|remember|connect\.sid|phpsessid|laravel_session|csrf)", re.I)


def parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
    parts = [p.strip() for p in header.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for part in parts[1:]:
        if not part:
            continue
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return name, attrs


def check_cookies(responses: list[HttpResponse]) -> list[Hit]:
    hits: list[Hit] = []
    seen: set[str] = set()
    for resp in responses:
        is_https = resp.url.lower().startswith("https://")
        for header in resp.get_all("set-cookie"):
            name, attrs = parse_set_cookie(header)
            if not name or name in seen:
                continue
            seen.add(name)
            # A cookie being deleted (expired / max-age=0) is not a risk.
            if attrs.get("max-age") == "0":
                continue
            sensitive = bool(SESSION_HINT.search(name))
            samesite = attrs.get("samesite", "").lower()
            if is_https and "secure" not in attrs:
                hits.append(Hit("cookie_no_secure", f"Cookie '{name}'"))
            if "httponly" not in attrs:
                hits.append(Hit("cookie_no_httponly", f"Cookie '{name}'",
                                severity="medium" if sensitive else "low"))
            if not samesite:
                hits.append(Hit("cookie_no_samesite", f"Cookie '{name}'"))
            elif samesite == "none" and "secure" not in attrs:
                hits.append(Hit("cookie_samesite_none_insecure", f"Cookie '{name}'"))
    return hits
