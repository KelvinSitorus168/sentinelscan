"""Command-line entry point: `sentinelscan <url>`."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__, report
from .models import SEVERITY_ORDER
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinelscan",
        description="Passive security check for a website you own: headers, TLS, cookies.")
    p.add_argument("url", help="Website to scan, e.g. example.com or https://example.com")
    p.add_argument("-f", "--format", choices=["text", "json", "md"], default="text")
    p.add_argument("--json", action="store_true", help="Shortcut for --format json")
    p.add_argument("-o", "--output", help="Write the report to this file")
    p.add_argument("-l", "--lang", choices=["en", "id"], default="en",
                   help="Report language: en (English) or id (Bahasa Indonesia)")
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="Network timeout in seconds")
    p.add_argument("--no-dns", action="store_true",
                   help="Skip DNS/email checks (SPF, DMARC, CAA, DNSSEC)")
    p.add_argument("--fail-on", choices=SEVERITY_ORDER[:-1] + ["none"], default="none",
                   help="Exit with code 1 if a finding at this severity or worse exists (for CI)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("-V", "--version", action="version", version=f"sentinelscan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    fmt = "json" if args.json else args.format
    try:
        result = scan(args.url, lang=args.lang, timeout=args.timeout, check_dns=not args.no_dns)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if fmt == "json":
        text = report.to_json(result)
    elif fmt == "md":
        text = report.to_markdown(result)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        text = report.to_text(result, color=color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        score = f" ({result['score']}/100)" if result["score"] is not None else ""
        print(f"Report written to {args.output} — grade {result['grade']}{score}")
    else:
        print(text)

    if not result["reachable"]:
        return 3
    if args.fail_on != "none":
        limit = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) <= limit for f in result["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
