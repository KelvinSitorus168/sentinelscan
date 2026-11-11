"""Render a scan result as terminal text, JSON or Markdown."""

from __future__ import annotations

import json

COLORS = {"critical": "\033[1;35m", "high": "\033[1;31m", "medium": "\033[33m",
          "low": "\033[36m", "info": "\033[2m", "ok": "\033[32m", "bold": "\033[1m", "reset": "\033[0m"}

TEXT = {
    "en": {"target": "Target", "final": "Final URL", "platform": "Platform", "unknown": "unknown",
           "grade": "Grade", "score": "Score", "findings": "Findings", "passed": "Passed",
           "skipped": "Not tested", "why": "Why", "fix": "Fix", "evidence": "Evidence",
           "none": "No issues found.", "errors": "Notes", "tls": "TLS",
           "days": "days left", "title": "Security report",
           "unreachable": "Could not reach the site over HTTPS or HTTP, so nothing was graded. "
                          "Check the address, or whether this machine has internet access."},
    "id": {"target": "Target", "final": "URL akhir", "platform": "Platform", "unknown": "tidak diketahui",
           "grade": "Nilai", "score": "Skor", "findings": "Temuan", "passed": "Lolos",
           "skipped": "Tidak diuji", "why": "Kenapa berbahaya", "fix": "Cara memperbaiki",
           "evidence": "Bukti", "none": "Tidak ada masalah ditemukan.", "errors": "Catatan",
           "tls": "TLS", "days": "hari lagi", "title": "Laporan keamanan",
           "unreachable": "Website tidak bisa dihubungi lewat HTTPS maupun HTTP, jadi tidak ada penilaian. "
                          "Periksa alamatnya, atau apakah komputer ini terhubung ke internet."},
}


def to_json(result: dict) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False)


def to_text(result: dict, color: bool = True) -> str:
    t = TEXT.get(result["lang"], TEXT["en"])
    c = COLORS if color else {k: "" for k in COLORS}
    out = []
    out.append(f"{c['bold']}SentinelScan {result['version']}{c['reset']}  —  {t['title']}")
    out.append(f"{t['target']}: {result['target']}")
    if not result.get("reachable", True):
        out.append(f"\n{c['high']}{t['unreachable']}{c['reset']}")
        out.extend(f" - {e}" for e in result["errors"])
        return "\n".join(out)
    if result["final_url"]:
        out.append(f"{t['final']}: {result['final_url']} (HTTP {result['status']})")
    out.append(f"{t['platform']}: {', '.join(result['platform']) or t['unknown']}")
    tls_info = result.get("tls") or {}
    if tls_info.get("protocol"):
        extra = f", {tls_info['days_left']} {t['days']}" if "days_left" in tls_info else ""
        out.append(f"{t['tls']}: {tls_info['protocol']}{extra}")
    s = result["summary"]
    out.append(f"\n{c['bold']}{t['grade']}: {result['grade']}   {t['score']}: {result['score']}/100{c['reset']}   "
               f"(critical {s['critical']} · high {s['high']} · medium {s['medium']} · low {s['low']} · info {s['info']})\n")

    if result["findings"]:
        out.append(f"{c['bold']}{t['findings']}{c['reset']}")
        for f in result["findings"]:
            sev = f["severity"]
            out.append(f"\n {c[sev]}[{sev.upper()}]{c['reset']} {c['bold']}{f['title']}{c['reset']}")
            if f["evidence"]:
                out.append(f"   {t['evidence']}: {f['evidence']}")
            out.append(f"   {t['why']}: {f['why']}")
            out.append(f"   {t['fix']}: {f['fix']}")
    else:
        out.append(f"{c['ok']}{t['none']}{c['reset']}")

    if result["passed"]:
        out.append(f"\n{c['bold']}{t['passed']}{c['reset']}")
        out.extend(f" {c['ok']}✓{c['reset']} {p}" for p in result["passed"])
    if result["skipped"]:
        out.append(f"\n{t['skipped']}: {', '.join(result['skipped'])}")
    if result["errors"]:
        out.append(f"\n{t['errors']}:")
        out.extend(f" - {e}" for e in result["errors"])
    return "\n".join(out)


def to_markdown(result: dict) -> str:
    t = TEXT.get(result["lang"], TEXT["en"])
    s = result["summary"]
    lines = [f"# {t['title']}: {result['target']}", ""]
    if not result.get("reachable", True):
        lines.append(t["unreachable"])
        lines.extend(f"- {e}" for e in result["errors"])
        return "\n".join(lines) + "\n"
    lines.append("| | |\n|---|---|")
    lines.append(f"| **{t['grade']}** | **{result['grade']}** ({result['score']}/100) |")
    lines.append(f"| {t['final']} | {result['final_url'] or '-'} |")
    lines.append(f"| {t['platform']} | {', '.join(result['platform']) or t['unknown']} |")
    tls_info = result.get("tls") or {}
    if tls_info.get("protocol"):
        lines.append(f"| {t['tls']} | {tls_info['protocol']}"
                     + (f", {tls_info['days_left']} {t['days']}" if "days_left" in tls_info else "") + " |")
    lines.append(f"| Scanned | {result['scanned_at']} (SentinelScan {result['version']}) |")
    lines.append("")
    lines.append(f"**critical {s['critical']} · high {s['high']} · medium {s['medium']} · "
                 f"low {s['low']} · info {s['info']}**")
    lines.append("")
    lines.append(f"## {t['findings']}")
    if not result["findings"]:
        lines.append(t["none"])
    for i, f in enumerate(result["findings"], 1):
        lines.append(f"\n### {i}. [{f['severity'].upper()}] {f['title']}")
        if f["evidence"]:
            lines.append(f"- **{t['evidence']}:** `{f['evidence']}`")
        lines.append(f"- **{t['why']}:** {f['why']}")
        lines.append(f"- **{t['fix']}:** {f['fix']}")
    if result["passed"]:
        lines.append(f"\n## {t['passed']}")
        lines.extend(f"- ✅ {p}" for p in result["passed"])
    if result["skipped"]:
        lines.append(f"\n**{t['skipped']}:** {', '.join(result['skipped'])}")
    if result["errors"]:
        lines.append(f"\n## {t['errors']}")
        lines.extend(f"- {e}" for e in result["errors"])
    return "\n".join(lines) + "\n"
