---
name: sentinelscan
description: Passive security check of a live website the user owns or manages. Covers security headers, HTTPS redirect, TLS certificate and versions, cookie flags and CORS, with a grade and platform-specific fixes (Next.js, Vercel, Netlify, Nginx, Apache/LiteSpeed, Express, Cloudflare). Use when the user asks to scan, audit or check the security of a website or URL, or asks why a site got a poor security grade.
---

# SentinelScan: website security check

SentinelScan makes a few normal HTTPS requests to a site and reports what the
outside world can see: missing security headers, a weak TLS setup, insecure
cookies and risky CORS. Each finding comes with a fix for the platform the
site runs on.

## 1. Confirm the target

- Get the URL or domain. If the user gave several, scan them one at a time.
- If it isn't clear that the site belongs to the user (or that they are
  allowed to test it), ask once. The scan is passive (about five GET requests,
  the same traffic as a visitor), but the report is meant for the site's
  owner, so frame the results for the person who can fix them.

## 2. Run the scanner

From this skill's folder (Python 3.9+; core needs no deps):

```bash
python3 scripts/scan.py <url> --json --lang <en|id>
```

DNS/email checks (SPF, DMARC, CAA, DNSSEC) need `dnspython`. If it isn't
installed the scan still runs and reports those as not tested with a note; to
enable them, `pip install dnspython`. Use `--no-dns` to skip them deliberately.

- Use `--lang id` when the user writes in Bahasa Indonesia and `en` otherwise.
  Write your own explanation in the user's language either way.
- Parse the JSON. Key fields: `grade`, `score`, `summary`, `findings[]` (each
  has `severity`, `title`, `why`, `fix`, `evidence`, `ref`), `passed[]`,
  `skipped[]`, `platform[]`, `tls`, `notes[]` (each `{id, detail}`).
- **If `reachable` is `false`** (grade `N/A`, exit code 3), nothing answered.
  Either the address is wrong or the site is down, or (if `notes` show DNS
  or proxy failures for a site that is obviously up) this environment has no
  outbound access. Tell the user, and ask them to run
  `python3 scripts/scan.py <url> -f md` on their own machine and paste the output.
  You can then explain it the same way.

## 3. Explain the results

Lead with the grade and the one or two things that matter most. Then:

1. Go through the findings from most to least severe. For each one: what it
   means in plain words, the evidence, and the fix. Group the low-severity
   header findings together, because one config block fixes all of them.
2. **Give fixes for the detected platform.** Read `references/fixes.md` and
   use the section named by each finding's `ref` (`headers`, `csp`,
   `https-redirect`, `tls`, `cookies`, `cors`, `info-leak`, `dns-email`,
   `securitytxt`). Pick the snippet
   for the platform in `platform[]`. If the platform is unknown, ask what the
   site runs on, or give the Nginx and Apache versions.
3. Name what passed. It shows the scan was thorough, and it keeps the
   user from changing things that already work.
4. Name `skipped` checks honestly ("TLS versions could not be tested from
   here"). Never present a skipped check as passed.

Calibrate the advice:
- **CSP**: never paste a strict CSP straight into production. Recommend the
  report-only starter from `references/fixes.md#csp` first, because a wrong
  CSP breaks the site.
- **HSTS `includeSubDomains`/`preload`**: only once every subdomain serves
  HTTPS.
- **`cors_wildcard` (info)**: usually fine for public APIs and assets.
- A grade is a summary, not proof of security. The scanner only sees response
  headers and TLS. It cannot see application bugs (SQL injection, broken
  access control, leaked secrets in code).

## 4. Offer to apply the fix

If the site's code or config is available here (for example `next.config.js`,
`vercel.json`, `netlify.toml`/`_headers`, an nginx conf, `.htaccess`, or an
Express app), offer to make the change. Show the diff, apply it after the user
agrees, and remind them it takes effect only after the next deploy. Then offer
to scan again.

## Other output options

- `-f md -o report.md` writes a Markdown report the user can keep or share.
- `--fail-on high` exits with code 1 when there are high or critical findings.
  It's useful in CI (see the README for a GitHub Actions example).
