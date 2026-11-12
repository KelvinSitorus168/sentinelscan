# Changelog

All notable changes to SentinelScan are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-11-12

### Added
- **DNS & email authentication checks** (optional, needs `dnspython`):
  - SPF: missing, `+all`/bare `all` (high), `?all` neutral, duplicate records.
  - DMARC: missing, `p=none` monitor-only.
  - CAA record presence.
  - DNSSEC presence (heuristic, info-level).
  - SPF/DMARC "missing" is medium when the domain has MX records, low otherwise.
- **security.txt check** — flags a missing `/.well-known/security.txt`.
- `--no-dns` flag, `[dns]` install extra, and fix snippets for SPF/DMARC/CAA/
  DNSSEC/security.txt in `references/fixes.md`.
- `notes[]` now includes `dnspython_missing` when DNS checks are skipped.

### Notes
- The core scanner remains dependency-free; DNS checks degrade gracefully to
  "not tested" when `dnspython` is absent.

## [0.1.1] - 2026-11-12

### Fixed
- **Broken-TLS sites are now scanned instead of reported unreachable.** Sites
  with an expired/self-signed certificate or a TLS 1.0-only endpoint are
  retried with a permissive TLS context, so their headers are still checked.
- **New critical finding `no_modern_tls`** when a server offers no TLS 1.2/1.3
  (previously such servers looked "unreachable").
- **Crash (`UnboundLocalError`) on sites with an untrusted certificate** during
  TLS inspection.
- **Redirect check no longer reads as "not tested" when port 80 is closed and
  HSTS is set.** A closed HTTP port plus HSTS is the strongest posture, so the
  check now passes.

### Changed
- Scan notes (e.g. "port 80 refused") are now translated in `--lang id` reports
  and carried in the JSON as structured `notes[]` (`{id, detail}`) instead of
  the old English-only `errors[]`.

### Added
- Regression tests against local HTTPS servers for untrusted certificates,
  TLS 1.0-only endpoints, and the port-80-closed + HSTS case.

## [0.1.0] - 2026-11-11

### Added
- Initial release: passive checks for security headers, HTTPS redirect, TLS
  certificate and versions, cookie flags and CORS.
- Bilingual (English / Bahasa Indonesia) reports in text, JSON and Markdown.
- Platform-specific fixes for Next.js, Vercel, Netlify, Nginx, Apache/LiteSpeed,
  Express and Cloudflare.
- CLI (`sentinelscan`), Claude skill (`SKILL.md`), and GitHub Actions example.
