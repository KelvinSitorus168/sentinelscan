# Fix snippets by platform

Each section matches a finding's `ref` field. The baseline header set in
**headers** fixes most low and medium findings in one change.

---

## headers

The recommended baseline:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

Use `X-Frame-Options: SAMEORIGIN` if the site embeds its own pages in
iframes. Add `includeSubDomains` only when every subdomain serves HTTPS.

### Next.js (`next.config.js` / `next.config.mjs`)

```js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
];

module.exports = {
  poweredByHeader: false, // removes X-Powered-By: Next.js
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  },
};
```

### Vercel (any framework, `vercel.json`)

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" }
      ]
    }
  ]
}
```

### Netlify (`_headers` file in the publish directory)

```
/*
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```

### Nginx (inside the `server { listen 443 ssl; ... }` block)

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;
server_tokens off;
```

Watch out: if a `location` block has its own `add_header`, it **replaces**
all inherited ones, so repeat the headers there or put them in an included
snippet file. Reload with `sudo nginx -t && sudo systemctl reload nginx`.

### Apache / LiteSpeed (`.htaccess`, shared hosting such as cPanel)

```apache
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "DENY"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"
  Header always unset X-Powered-By
  Header unset X-Powered-By
</IfModule>
```

### Express (Node.js)

```js
const helmet = require('helmet');   // npm i helmet
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,      // enable after testing, see "csp"
  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
```

### Cloudflare (when the origin can't be changed)

Add a response-header rule (Rules → Transform Rules → *Modify Response
Header*) for each header above. Enable HSTS under SSL/TLS → Edge Certificates.

---

## csp

A Content-Security-Policy that is too strict breaks the site, so roll it out
in two steps.

**Step 1: report only.** Nothing is blocked; violations show in the browser
console.

```
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'
```

Browse the site, read the console, and add the domains it really needs, for
example `script-src 'self' https://www.googletagmanager.com` or
`connect-src 'self' https://<project>.supabase.co`.

**Step 2: enforce it.** Rename the header to `Content-Security-Policy`.

To remove `'unsafe-inline'` from `script-src`, use nonces. Next.js
(App Router) supports this through middleware: generate a nonce per request,
then use `script-src 'self' 'nonce-<value>' 'strict-dynamic'`. Search the
Next.js docs for "Content Security Policy nonce" for the current snippet.

---

## https-redirect

| Platform | How |
|---|---|
| Vercel / Netlify / GitHub Pages | Automatic once a custom domain has a certificate. On GitHub Pages, tick "Enforce HTTPS". |
| Cloudflare | SSL/TLS → Edge Certificates → **Always Use HTTPS** |
| Nginx | `server { listen 80; server_name example.com; return 301 https://$host$request_uri; }` |
| Apache / LiteSpeed `.htaccess` | see below |

```apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
```

No certificate yet? On a VPS: `sudo certbot --nginx -d example.com`
(Let's Encrypt, free). On shared hosting, turn on the free AutoSSL or
Let's Encrypt option in the control panel.

---

## tls

**Certificate invalid or expiring:** renew it. With certbot, check that
`sudo certbot renew --dry-run` succeeds and that the systemd timer or cron job
exists. Managed platforms renew automatically, so an expiring certificate there
usually means the DNS no longer points at the platform.

**Old TLS versions (1.0 / 1.1):**

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
```

Cloudflare: SSL/TLS → Edge Certificates → Minimum TLS Version → **TLS 1.2**.

---

## cookies

Target for session and auth cookies: `Secure; HttpOnly; SameSite=Lax`.

```js
// Express + express-session
app.set('trust proxy', 1); // when behind Vercel/Nginx/Cloudflare
app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' }, /* ... */ }));

// Next.js (App Router)
cookies().set('session', value, { secure: true, httpOnly: true, sameSite: 'lax', path: '/' });
```

```php
// PHP (php.ini or before session_start)
session.cookie_secure = 1
session.cookie_httponly = 1
session.cookie_samesite = "Lax"
```

Laravel: in `config/session.php`, set `'secure' => true`,
`'http_only' => true`, `'same_site' => 'lax'` (or `SESSION_SECURE_COOKIE=true`
in `.env`).

Cookies that front-end JavaScript has to read, such as a theme preference,
can't be HttpOnly. That's fine as long as they hold nothing secret.

---

## cors

Never reflect any `Origin` back while `Access-Control-Allow-Credentials: true`
is set. Use an explicit allow-list:

```js
// Express
const cors = require('cors');
const allowed = ['https://example.com', 'https://admin.example.com'];
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowed.includes(origin)),
  credentials: true,
}));
```

`Access-Control-Allow-Origin: *` without credentials is fine for public data
such as a public API, fonts or images.

---

## info-leak

| Stack | Setting |
|---|---|
| Nginx | `server_tokens off;` |
| Apache | `ServerTokens Prod` and `ServerSignature Off` (main config, not .htaccess) |
| PHP | `expose_php = Off` in php.ini |
| Express | `app.disable('x-powered-by')` or use helmet |
| Next.js | `poweredByHeader: false` in next.config.js |
| ASP.NET | `<httpRuntime enableVersionHeader="false" />` |

Hiding versions doesn't fix vulnerabilities. It only makes targeting harder,
so keep the software itself updated.
