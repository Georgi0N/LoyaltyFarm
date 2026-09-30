# Hasad — Digital Loyalty Program for Farmers (Iraq)

A **commercial-grade, security-hardened** QR loyalty platform. Farmers scan a
cryptographically-secure code on each participating product to earn points, then
redeem points for agricultural rewards collected from authorized wholesalers.
One central Node.js backend + SQLite database powers three connected portals with
full **Arabic (RTL) / English (LTR)** support and a mobile-first design.

```
   Farmer Mobile Web App  ─┐
   Wholesaler Portal      ─┼──►  Express REST API  ──►  SQLite (central DB)
   Admin Dashboard        ─┘
```

- **Farmers** get a dead-simple flow: enter phone → OTP → Scan / Rewards / History.
- **Wholesalers** validate a redemption and confirm handover (with a safety prompt).
- **Admins** manage the whole program: farmers, products/SKUs, batches, secure QR
  generation, rewards, redemptions, wholesalers, **staff users & roles**, reports,
  **fraud alerts**, audit logs, and settings.

> Security is a first-class feature: the frontend is never trusted; every decision
> is enforced on the server, in the database, and in business logic. See
> **[SECURITY.md](SECURITY.md)** for the architecture and remaining risks.

## Architecture

- **Backend:** Node.js + Express, SQLite via `better-sqlite3` (synchronous, single
  connection → race-free transactions). Layered modules: `config`, `crypto`, `db`,
  `security`, `otp`, `fraud`, `settings`, `rbac`, `sessions`, `idempotency`,
  `services`, and role routers under `src/routes/`.
- **Frontend:** framework-free ES modules served statically — a shared design
  system (`assets/css`), i18n dictionary, and one script per portal. Chart.js +
  html5-qrcode via CDN.

## Required software

Node.js 18+ (tested on 22) and npm. A C toolchain for the `better-sqlite3` native
module (`build-essential` + `python3` on Debian/Ubuntu; Build Tools on Windows).

## Development setup

```bash
npm install
npm run reset      # rebuild schema + seed demo data (dev only)
npm start          # http://localhost:3000
```

| Portal | URL | Login |
| --- | --- | --- |
| **Farmer** | /farmer | mobile + OTP (dev OTP printed to console and shown on screen) |
| **Wholesaler** | /wholesaler | `baghdad` / `Wholesale@123` (also `basra`, `mosul`) |
| **Admin** | /admin | `admin`/`admin123` (SUPER_ADMIN), `manager`/`Manager@123`, `viewer`/`Viewer@123` |

Demo product QR tokens for scan testing are written to `data/demo-tokens.txt`
(dev only). Real batches: **Admin → QR Codes → Generate** downloads a print file
containing the tokens + `/c/<token>` scan URLs — the only place raw tokens appear.

## User roles

| Role | Capabilities |
| --- | --- |
| `SUPER_ADMIN` | Everything, incl. **staff user management** + settings |
| `PROGRAM_MANAGER` | Products, batches, QR, rewards, wholesalers, redemptions, reports, fraud |
| `OPERATIONS` | Batches, QR generation/blocking, fraud reviews, redemptions |
| `SUPPORT` | Farmers (block), redemptions (cancel/refund), fraud reviews |
| `REPORT_VIEWER` | Read-only dashboard / reports / redemptions |
| `WHOLESALER` | Separate account type: validate + confirm reward handover |

Roles map to least-privilege permission sets checked on **every** endpoint. The
last active SUPER_ADMIN is protected from disable/demote. Full setup steps for
adding/disabling/resetting accounts: **[LOGIN_SETUP.txt](LOGIN_SETUP.txt)**.

## Main commands

| Command | Purpose |
| --- | --- |
| `npm start` | Start the server |
| `npm run migrate` | Create/upgrade the DB schema (idempotent) |
| `npm run reset` | Rebuild schema + seed demo data (**dev only**; refuses in prod) |
| `npm run create-super-admin` | Securely bootstrap the first production admin (hidden password prompt) |
| `npm test` | 60 backend security/attack/concurrency checks (server must be running) |
| `npm run smoke` | Headless DOM render test of all portals (server must be running) |

## Environment variables

See **[.env.example](.env.example)** (copy to `.env`). Key vars: `APP_ENV`,
`APP_URL`, `PORT`, `DATABASE_URL` (reserved for Postgres), `SESSION_SECRET`,
`QR_HMAC_SECRET`, `OTP_HMAC_SECRET`, `REDEMPTION_HMAC_SECRET`, `COOKIE_SECURE`,
`TRUST_PROXY`, `OTP_DELIVERY`, `OTP_DEV_ECHO`, `OTP_PROVIDER`, `OTP_API_KEY`,
`WHATSAPP_API_KEY`, `EMAIL_PROVIDER`. In production the server **fails closed** if
secrets are missing/weak.

## Database

SQLite at `data/app.db` (WAL). Foreign keys, UNIQUE + CHECK constraints, indexes,
and **append-only triggers** on the points ledger and audit log. Schema is
versioned (`SCHEMA_VERSION` in `src/db.js`) and created automatically. Only token
**hashes** are stored (never raw QR/redemption secrets). Large lists (farmers, QR,
redemptions, audit) are **server-side paginated**.

## Testing

```bash
npm start                    # terminal 1
npm test                     # terminal 2 → 60 checks (auth, OTP, QR double-spend,
                             #   concurrency, redemption, RBAC/IDOR, mass-assignment,
                             #   CSRF, lockout, fraud holds, user mgmt, pagination…)
npm run smoke                # portals render with no runtime errors (jsdom)
```

## Production deployment

Full instructions (HTTPS/reverse proxy, secrets, migrations, first admin,
backups, monitoring, scaling): **[DEPLOYMENT.md](DEPLOYMENT.md)**.

## Documentation

- **[SECURITY.md](SECURITY.md)** — security architecture + known limitations
- **[DEPLOYMENT.md](DEPLOYMENT.md)** — production deployment
- **[LOGIN_SETUP.txt](LOGIN_SETUP.txt)** — accounts, roles, operational how-to
- **[.env.example](.env.example)** — configuration reference
