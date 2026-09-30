# Deployment Guide — Hasad Loyalty

This guide takes another developer from a clean server to a running production
instance. The app is a single Node.js service (Express) that serves the REST API
and the three static portals, backed by SQLite.

---

## 1. Requirements

- **Node.js 18+** (built and tested on Node 22) and npm.
- A Linux host (or any OS Node supports). A build toolchain for `better-sqlite3`
  native module — on Debian/Ubuntu: `apt-get install -y build-essential python3`.
- A reverse proxy that terminates **TLS/HTTPS** (nginx / Caddy / a cloud LB).
- Persistent disk for `data/` (the SQLite database + generated print files).

## 2. Get the code & install

```bash
git clone <your-repo> hasad && cd hasad
npm ci --omit=dev        # production deps only (skips jsdom devDependency)
```

## 3. Configure environment

```bash
cp .env.example .env
# Edit .env — set APP_ENV=production and STRONG unique secrets:
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"  # run 4x
```

Set at minimum: `APP_ENV=production`, `APP_URL=https://your-domain`,
`SESSION_SECRET`, `QR_HMAC_SECRET`, `OTP_HMAC_SECRET`, `REDEMPTION_HMAC_SECRET`,
`COOKIE_SECURE=true`, `OTP_DEV_ECHO=false`, and your OTP provider
(`OTP_DELIVERY=sms`, `OTP_PROVIDER`, `OTP_API_KEY`).

> In production the process **refuses to start** if any secret is missing/weak,
> and never echoes OTPs. Keep `.env` out of source control (it is gitignored).

## 4. Database setup & migration

The schema is created/upgraded automatically on first load. To run it explicitly:

```bash
npm run migrate      # creates data/app.db with the current schema (idempotent)
```

Do **not** run `npm run seed` / `npm run reset` in production (they refuse to run
when `APP_ENV=production` unless forced, and are for demo data only).

**Rollout upgrades:** this build uses a versioned schema (`SCHEMA_VERSION` in
`src/db.js`). Take a backup before deploying a version that bumps it. For
data-preserving migrations across versions, add explicit `ALTER TABLE` steps
(the current dev flow rebuilds; production migrations must preserve data).

## 5. First Super Admin

```bash
npm run create-super-admin      # prompts for username / name / password (hidden)
```

No default admin credentials ship to production.

## 6. Build & start

There is no build step (server-rendered static assets). Start the server:

```bash
APP_ENV=production node server.js
# or with a process manager (recommended):
pm2 start server.js --name hasad --update-env
pm2 save && pm2 startup
```

The app listens on `PORT` (default 3000). Put it behind your reverse proxy.

## 7. HTTPS / reverse proxy (nginx example)

```nginx
server {
  listen 443 ssl http2;
  server_name your-domain;
  ssl_certificate     /etc/letsencrypt/live/your-domain/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/your-domain/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
server { listen 80; server_name your-domain; return 308 https://$host$request_uri; }
```

Set `TRUST_PROXY=1` (or the real proxy count) so client IPs and rate limiting are
correct. The app also enables HSTS + an HTTP→HTTPS redirect when
`APP_ENV=production`.

## 8. File permissions

- `data/` must be writable by the service user; keep it **off** the public web root.
- `data/app.db`, `data/exports/*.csv` (QR print files) and any `.env` contain
  sensitive data — restrict to the service user (`chmod 600` / `700`).
- Delete QR print files from `data/exports/` after they have been sent to the
  label printer.

## 9. Scheduled jobs / maintenance

- **Backups** (see below) — nightly.
- Optional: prune old `audit_logs` / expired `otp_challenges` / revoked
  `sessions` on a schedule to keep the DB lean (all are safe to archive/delete
  except keep audit history per your retention policy).

## 10. Backups

- SQLite: back up with the online backup API or `sqlite3 data/app.db ".backup
  /backups/app-$(date +%F).db"` (safe with WAL). Encrypt backups at rest.
- Store copies **off-site**, define a retention policy, and **test restores**
  regularly. Backups contain personal data (phone numbers) — protect access.

## 11. Monitoring & logs

- The app logs to stdout with a request id on errors; ship logs to your platform
  (journald/pm2/cloud). Logs never contain passwords, OTPs, or raw tokens.
- Alert on: elevated 5xx / error rate, failed-login spikes, OTP send spikes,
  QR-validation spikes, and new HIGH-risk fraud reviews (visible in the admin
  Fraud Alerts + audit log).

## 12. Post-deploy verification

```bash
# with the server running:
node scripts/security-tests.js   # 60 backend attack/authz/concurrency checks
node scripts/dom-smoke.js        # portals render with no runtime errors
```

Then manually: create a product → SKU → batch → generate QR (download print
file) → farmer OTP login → scan → redeem → wholesaler confirm → check admin
dashboard/audit.

## 13. Scaling notes (future)

Correctness currently relies on SQLite's single-writer model + in-process rate/
session state (single node). For horizontal scale, migrate to **PostgreSQL**
(same conditional-UPDATE / transaction pattern) and move sessions + rate-limit
counters to **Redis**. The data layer is structured for this. See SECURITY.md →
Known Limitations.
