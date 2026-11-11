# 🛡️ SentinelScan

**A passive security check for websites you own, with fixes for the platform
you run on.** It works as a command-line tool and as a
[Claude](https://claude.ai) skill.

```
$ sentinelscan example.com --lang id

Nilai: C   Skor: 71/100   (critical 0 · high 1 · medium 0 · low 3 · info 0)

 [HIGH] Header Strict-Transport-Security (HSTS) tidak ada
   Kenapa berbahaya: Tanpa HSTS, browser masih bisa mencoba HTTP biasa lebih dulu ...
   Cara memperbaiki: Kirim header: Strict-Transport-Security: max-age=31536000; includeSubDomains
 ...
```

- **Zero dependencies.** Pure Python standard library (3.9+).
- **Bilingual reports.** English and Bahasa Indonesia (`--lang id`).
- **Fixes, not just warnings.** Ready-to-paste config for Next.js, Vercel,
  Netlify, Nginx, Apache/LiteSpeed, Express and Cloudflare
  ([references/fixes.md](references/fixes.md)).
- **Passive.** About five ordinary GET requests, the same as a visitor. No
  fuzzing, no brute force, no exploit payloads.
- **CI-ready.** `--fail-on high` returns exit code 1 for your pipeline.

## What it checks (v0.1)

| Area | Checks |
|---|---|
| Transport | HTTPS available · HTTP → HTTPS redirect · certificate valid / expiring · TLS 1.0/1.1 still accepted |
| Headers | HSTS · Content-Security-Policy (incl. `unsafe-inline` / `unsafe-eval`) · clickjacking (X-Frame-Options / frame-ancestors) · X-Content-Type-Options · Referrer-Policy · Permissions-Policy |
| Disclosure | `Server` version · `X-Powered-By` |
| CORS | Wildcard origin · any-origin reflection with credentials |
| Cookies | `Secure` · `HttpOnly` (stricter for session-like names) · `SameSite` · `SameSite=None` without `Secure` |

Findings are scored critical (−40), high (−20), medium (−10) and low (−3),
which gives a grade from **A+** to **F**. Cookie values are never printed or
stored.

## Install & use

```bash
# from GitHub
pipx install git+https://github.com/KelvinSitorus168/sentinelscan
# or from a clone
git clone https://github.com/KelvinSitorus168/sentinelscan && cd sentinelscan && pip install .

sentinelscan example.com                    # colored terminal report
sentinelscan example.com --lang id          # Bahasa Indonesia
sentinelscan example.com -f md -o report.md # Markdown report
sentinelscan example.com --json             # machine-readable
```

You can also run it without installing: `python3 scripts/scan.py example.com`.

## Use it as a Claude skill

Ask Claude in plain language, for example *"check the security of
mysite.com"* or *"cek keamanan website saya"*. Claude runs the scan, explains
each finding, gives the fix for your platform, and can edit your
`next.config.js`, `vercel.json` or `.htaccess` for you.

- **Claude Code:** copy this folder to `~/.claude/skills/sentinelscan/`
  (or `.claude/skills/` inside a project).
- **Claude app:** zip this folder and upload it in Claude's skills settings.

The skill needs network access to reach the target site. If Claude's
environment can't reach it, Claude asks you to run the CLI locally and paste
the result.

## GitHub Actions

```yaml
# .github/workflows/security-headers.yml
name: Security headers
on:
  schedule: [{ cron: "0 2 * * 1" }]   # every Monday
  workflow_dispatch:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install git+https://github.com/KelvinSitorus168/sentinelscan
      - run: sentinelscan https://your-site.com -f md -o report.md --fail-on high
      - if: always()
        run: cat report.md >> "$GITHUB_STEP_SUMMARY"
```

## Responsible use

Scan sites you own or are allowed to test. SentinelScan only sends normal
requests, but a security report belongs to the site owner. A good grade means
the *visible configuration* is solid. It says nothing about application bugs
like SQL injection, broken access control or secrets in code.

## Roadmap

- [x] v0.1: headers, TLS, cookies, CORS, bilingual reports, Claude skill
- [ ] v0.2: DNS & email security (SPF, DMARC, CAA, DNSSEC), `security.txt`, mixed content
- [ ] v0.3: opt-in exposed-file check (`/.env`, `/.git/`, source maps) and HTML report
- [ ] Later: web UI (FastAPI) and batch scanning

## Development

```bash
python3 -m unittest discover -s tests -v
```

Contributions welcome. New checks go in `sentinelscan/checks/`, their
bilingual text in `sentinelscan/catalog.py`, and fix snippets in
`references/fixes.md`.

---

### 🇮🇩 Bahasa Indonesia

SentinelScan memeriksa keamanan dasar website milikmu dari luar: header
keamanan, HTTPS dan sertifikat TLS, flag cookie, dan CORS. Hasilnya nilai A+
sampai F, penjelasan bahaya tiap temuan dalam bahasa sederhana, dan kode
perbaikan siap-tempel sesuai platform (Next.js, Vercel, Netlify, Nginx,
Apache/LiteSpeed untuk shared hosting, Express, Cloudflare).

Pakai `--lang id` untuk laporan berbahasa Indonesia. Kalau dipasang sebagai
skill Claude, cukup minta *"cek keamanan website saya"*.

## License

MIT © Kelvin Sitorus
