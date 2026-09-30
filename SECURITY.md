# Hasad Loyalty — Security Architecture

This document describes how the platform defends against fraud and abuse, and is
honest about what it does **not** yet do. No system is "unhackable"; the goal is
**defense in depth** — making fraud financially difficult, technically difficult,
**detectable, auditable, and recoverable** — enforced at the database, backend,
authentication, business-logic, and (where configured) infrastructure layers.

**The browser is never the security boundary.** Every decision that matters
(point values, balances, eligibility, statuses, prices, roles) is made on the
server against the database. The frontend only submits tokens and identifiers.

Automated proof: `node scripts/security-tests.js` runs **60 attack / concurrency
/ authorization checks** against a live server, and `node scripts/dom-smoke.js`
renders every portal in a headless DOM asserting no runtime errors (see *Testing*).

---

## 1. Authentication architecture

| Actor | Method |
| --- | --- |
| **Farmer** | Mobile number + **OTP** (one-time passcode). Mobile is the unique identity. |
| **Wholesaler** | Individual username + password (scrypt), per-account lockout. |
| **Admin** | Individual username + password (scrypt) + optional **TOTP MFA**, role-based. |

- Sessions are **httpOnly, SameSite=Lax, signed** cookies (`Secure` in production).
- On every login the **session id is regenerated** (session-fixation defence).
- A server-side `sessions` table adds **revocation** ("log out all devices"),
  **idle timeout** (30 min) and an **absolute cap** (7 days), enforced on every request.
- Passwords are hashed with **scrypt** (memory-hard, built into Node, no native
  build). *Production recommendation:* upgrade to **Argon2id** (see Known Limitations).

## 2. OTP security (`src/otp.js`)

- Codes are random digits; only an **HMAC(phone : code)** is stored — never
  plaintext, never logged in production.
- **Single-use**, short **TTL** (default 300s), and a single active code per number.
- **Capped verify attempts** per challenge (default 5) → brute force is bounded to
  a handful of guesses per issued code.
- **Send limits** (per number, per window) + **resend cooldown**.
- Rate limited additionally by IP at the route (send + verify).
- **Anti-enumeration:** `request-otp` returns a generic success whether or not the
  number is registered; failure reasons are generic (`invalid` / `expired`).
- Delivery is pluggable. Dev prints to the server console; **production must wire a
  real SMS/WhatsApp provider** in `deliver()`.

## 3. Account uniqueness & multi-account abuse

- `farmers.mobile` has a **UNIQUE** DB constraint — one account per number,
  enforced at the database, not just the app.
- Numbers are **normalized** to one canonical Iraqi form (`07XXXXXXXXX`) before
  storage/comparison.
- Attackers may still obtain multiple SIMs, so a **fraud engine** (below) scores
  behaviour rather than relying on identity alone. IP is only ever a weak secondary
  signal — **shared Wi-Fi / carrier NAT never auto-blocks** legitimate farmers.

## 4. Product QR security

- Tokens are **cryptographically random** (`crypto.randomBytes`) over an
  unambiguous alphabet, **26 symbols ≈ 128 bits** of entropy — non-sequential and
  practically unguessable (e.g. `8FK29XQ7MPL4D2A9…`). No sequential IDs, batch
  counters, product IDs or primary keys appear in the QR.
- **Only the HMAC-SHA256 of each token is stored** (`token_hash`, keyed by
  `QR_HMAC_SECRET`). A database leak therefore does **not** expose usable physical
  codes. Raw tokens exist only at generation time, written once to a print file.
- **Point value comes from the QR/batch record on the server**, never the client.

**Claim flow (single transaction):** hash token → find record → confirm exists,
campaign/product/SKU/batch **active**, status **unused** → fraud score → atomic
`UPDATE … WHERE status='unused'` → post ledger entry + move balance → commit.
Reused → *"already claimed"*; invalid/blocked/ineligible → rejected and audited.

## 5. Double-spend prevention (critical)

- Every points operation is a **`better-sqlite3` transaction** (synchronous,
  single-connection) with a **conditional UPDATE** (`WHERE status='unused'` /
  `WHERE quantity>0` / `WHERE status='pending'`). Only the first attempt changes a
  row; the rest see 0 changes and are rejected.
- Proven by tests: **50 simultaneous claims of one QR → exactly 1 success**;
  **20 simultaneous redemption confirms → exactly 1 success**; ledger credited once.

## 6. Idempotency (`src/idempotency.js`)

- Claim and redeem accept an `Idempotency-Key` header. A retried request with the
  same key returns the stored original response instead of executing twice — so a
  flaky-network double-tap cannot double-credit or double-redeem. Verified by test.

## 7. Points ledger

- `points_transactions` is an **append-only ledger** (`type`, `source`, signed
  `points`, `prev_balance`, `balance_after`, actor, references). **DB triggers ABORT
  any UPDATE/DELETE** — history is immutable.
- The cached `farmers.points_balance` is moved inside the same transaction and has a
  **`CHECK (points_balance >= 0)`** constraint (overspend impossible at the DB level).
- **Admin adjustments are never silent:** every manual change writes an
  `ADMIN_ADJUSTMENT` ledger row with actor, reason, and previous/new balance, plus an
  audit entry. Reconciliation test asserts every balance equals its ledger sum.

## 8–10. Reward redemption security

- Redemption tokens are **separate** from product tokens, cryptographically random
  (~160 bits), and looked up by **hash** for the wholesaler.
- States: `pending → redeemed | expired | cancelled`. Points/stock are deducted
  atomically at creation; the wholesaler confirmation is an atomic conditional
  UPDATE (single-use). **Configurable expiry** (default 30 days); expired codes fail
  validation. **Admin cancel refunds** via a new ledger entry (history never edited).

## 11–12. Wholesaler & admin security

- **No shared passwords** — every wholesaler/admin is an individual account with
  scrypt hashing and **lockout** after repeated failures.
- **Admin MFA (TOTP)** is supported (self-service enable in the dashboard; RFC 6238,
  verified server-side).
- **Least-privilege roles** (`src/rbac.js`): `SUPER_ADMIN`, `PROGRAM_MANAGER`,
  `OPERATIONS`, `REPORT_VIEWER`, `SUPPORT`. Every admin endpoint checks a specific
  **permission** (e.g. `qr.generate`), not a boolean `admin=true`. The UI also hides
  disallowed sections, but the **server is authoritative**.

## 12b. Staff user management & credential lifecycle

- **User management is SUPER_ADMIN-only** (`users.manage`). Creating a user issues a
  **temporary password** (shown once, stored hashed) that **forces a change at first
  login** (`must_change_password`). Password change requires the current password,
  enforces the staff policy, and **revokes the user's other sessions**.
- **Admin-initiated reset** issues a new temp password and revokes all of the target's
  sessions. **Revoke-sessions** and **"log out all devices"** are available.
- **Soft delete:** accounts move between `active / disabled / archived` (disabled &
  archived cannot log in and are force-logged-out); records are preserved so audit and
  transaction references remain intact.
- **Last-active-SUPER_ADMIN protection:** the system refuses to disable, archive, or
  demote the final SUPER_ADMIN, so it can never be locked out.
- Every user/role/status/password/session change writes an audit entry. First
  production admin is created via the `create-super-admin` CLI (no shipped defaults).

## 13. Authorization on every request (IDOR)

- Farmer endpoints derive the farmer from the **session**, never a URL id — there is
  no `/farmer/:id` to abuse. Cross-role and cross-object access is rejected.
- Role guards re-check **live account status** each request, so a blocked user is
  stopped mid-session. Tests cover farmer→admin, farmer→wholesaler, anonymous→private,
  and RBAC least-privilege.

## 14–17. Session, CSRF, XSS, SQL injection

- **Sessions:** see §1 (fixation, revocation, idle/absolute expiry, httpOnly/Secure).
- **CSRF:** double-submit token required on all mutating requests; verified with
  constant-time comparison. Missing/invalid → 403 (tested).
- **XSS:** all dynamic output is HTML-escaped client-side (`App.esc`); strict CSP,
  `X-Content-Type-Options`, `frame-ancestors 'none'`, Referrer-Policy, Permissions-Policy.
- **SQL injection:** **100% parameterized** prepared statements (better-sqlite3);
  no string concatenation of user input anywhere.

## 18. Mass assignment

- No route spreads `req.body` into a query. Every insert/update uses an explicit
  allow-list of fields. Injecting `role`, `points_balance`, `status`, `id` is ignored
  (tested for registration).

## 19–20. Rate limiting & bot defence

- Layered limits: global (per IP), API (per IP), and **per-action** limits on login,
  OTP send, OTP verify, scan, redeem, and lookup. Scan/redeem are keyed **per farmer
  session** (not IP) so shared connections don't throttle innocents.
- The fraud engine provides progressive throttling / hold-for-review as an adaptive
  layer. (A CAPTCHA-on-elevated-risk step is a documented future hook.)

## 21–23. QR enumeration, screenshot risk, device/location signals

- 128-bit tokens + hashed storage + invalid-attempt auditing make enumeration
  impractical; repeated invalid scans raise the fraud score and are logged.
- **Physical copy risk is acknowledged** (see Known Limitations) with operational
  mitigations. Location/device data are treated as **signals**, not identity.

## 24. Fraud / risk engine (`src/fraud.js`, `src/settings.js`)

Behavioural signals over rolling windows — scan velocity, invalid-scan rate,
redemption velocity, account age — produce a **0–100 score** and a band:

| Band | Score | Action |
| --- | --- | --- |
| LOW | 0–29 | allow |
| MEDIUM | 30–69 | allow + log (extra verification hook) |
| HIGH | 70–100 | **hold** the transaction for manual admin review |

A HIGH claim **consumes the QR but withholds the points** into an open review;
approval credits them via the ledger. **Thresholds are admin-configurable**
(`settings` table, `settings.manage` permission). Tested end-to-end.

## 25. Audit logs

- `audit_logs` is **append-only** (UPDATE/DELETE blocked by triggers). It records
  logins/failures, permission denials, blocks, adjustments, product/batch/QR/reward
  creation, QR generation + suspicious/duplicate/ineligible scans, redemptions,
  wholesaler confirmations, MFA and settings changes — with actor, action, target,
  request id, IP, severity, and time. **Secrets (passwords, OTPs, raw tokens) are
  never logged.** Phone numbers are masked in logs.

## 26–27. Database & token storage

- Foreign keys ON; **UNIQUE** on `farmers.mobile`, `product_qr_codes.token_hash`,
  `redemptions.token_hash`, `redemptions.code`, usernames; **CHECK** constraints on
  balances, stock, and cost; indexes on hot paths. Invalid states can't be persisted.
- Token **hashes** (HMAC-SHA256) stored, not plaintext (§4).

## 28. Secrets (`src/config.js`, `.env.example`)

- All secrets load from environment variables. **Production fails closed**: the
  process refuses to start with missing/weak/default secrets. `.env` is gitignored;
  `.env.example` ships placeholders only. Nothing is hard-coded.

## 29–31. HTTPS, headers, error handling

- **HTTP→HTTPS 308 redirect** and **HSTS** enabled when `NODE_ENV=production`;
  Secure cookies. Helmet sets CSP + hardening headers.
- Errors return a **generic** `{ error, requestId }`; full stack traces go only to
  the server log, correlated by request id. No SQL/schema/paths leak to clients.

## 32–33. File upload & CSV safety

- No public file-upload endpoint exists (reward images are referenced by key), so the
  upload attack surface is nil in this prototype. **If** uploads are added, validate
  MIME + extension + size + magic bytes, randomise names, and store outside the web root.
- **CSV formula injection is neutralised**: exported cells beginning with `= + - @`
  (or tab/CR) are quote-prefixed. QR print-file download validates the filename against
  a strict pattern and resolves strictly inside `data/exports` (no path traversal).

## 34–39. Business-logic, concurrency, transaction consistency, overrides, generation

- All the business-logic abuse cases in the brief are covered and tested (reuse,
  simultaneous 50×, injected values, foreign wallet, insufficient points, changed
  reward cost, reused/expired redemption, blocked user, disabled product/batch, role
  tamper, cross-role calls, anonymous calls).
- Points + QR/redemption state change **atomically together** — never "QR used but no
  points" or "points deducted but no redemption".
- Admin overrides require permission + reason + audit entry.
- Bulk generation uses CSPRNG, verifies uniqueness, records the batch + a generation
  audit log, and produces a safe export file.

---

## Testing

```bash
npm install
npm run reset            # rebuild schema + seed demo data
node server.js           # terminal 1
node scripts/security-tests.js   # terminal 2  -> 43 checks
```

Coverage (60 checks): OTP (issue/verify/reuse/brute-force/enumeration),
duplicate-account, frontend-not-trusted, QR single-use/invalid/duplicate/idempotency,
**concurrency double-spend (claim + confirm)**, redemption (insufficient/idempotent/
confirm race), authorization/IDOR/RBAC, mass assignment, CSRF, lockout, fraud hold +
review, ledger immutability + audited adjustment, hash-only token storage, balance
reconciliation, **staff user management** (create/temp-password/forced-change,
session revocation on password change + reset, last-super-admin protection, disabled
login block), **redemptions admin list + pagination**. Plus `dom-smoke.js` renders
every portal (both languages, authed + unauthed) with zero runtime errors.

---

## KNOWN LIMITATIONS / REMAINING RISKS

These are **real** and must be addressed operationally or before production.

1. **Physical QR copying (operational, unavoidable in software).** A QR printed on a
   product can be photographed *before purchase* and claimed by someone who never
   bought it. No backend can fully prevent copying a visible code. Mitigations are
   **operational**: hidden **scratch-off** labels, tamper-evident seals, QR under the
   cap/seal, first-claim-wins (already enforced), plus the fraud engine's velocity and
   anomaly detection and per-batch/distributor monitoring for review.

2. **OTP/SMS delivery is not wired.** Dev prints the code to the console and (when
   `OTP_DEV_ECHO=true`) echoes it to the client. **Production must** integrate a real
   SMS/WhatsApp provider in `src/otp.js` and set `OTP_DEV_ECHO=false`, `OTP_DELIVERY=sms`.

3. **Password hashing is scrypt, not Argon2id.** scrypt is strong and memory-hard, but
   the brief asks for Argon2id. Swap in the `argon2` package (native) in `src/crypto.js`
   for production; the hash format is already self-describing to allow migration.

4. **SQLite + in-memory rate-limit/session store = single-node.** Correctness relies on
   better-sqlite3's synchronous single-connection model. For multi-process/HA, migrate
   to **PostgreSQL** (use `SELECT … FOR UPDATE` / the same conditional-UPDATE pattern),
   and move sessions + rate-limit counters to **Redis**. The code is structured for this.

5. **CSP still allows `'unsafe-inline'`** for scripts/styles because the static HTML
   uses inline blocks. Move inline JS/CSS to external files (or add per-request nonces)
   to drop `'unsafe-inline'` and fully close the XSS gap.

6. **MFA is optional and TOTP-only.** No backup codes / recovery flow, no WebAuthn.
   Enforce MFA for all admins and add a secure recovery process in production.

7. **HTTPS/HSTS, backups, and monitoring are infrastructure concerns.** The app enables
   HTTPS redirect + HSTS + Secure cookies when `NODE_ENV=production`, but TLS
   termination, **encrypted off-site backups with restore testing**, log shipping, and
   alerting (failed logins, OTP spikes, QR-validation spikes, fraud alerts, error rate)
   must be provided by the deployment environment.

8. **Demo artefacts must not ship.** `data/demo-tokens.txt`, seeded demo accounts, and
   default credentials (`admin/admin123`, etc.) are for the prototype only. Production
   must remove them, set `NODE_ENV=production`, `OTP_DEV_ECHO=false`, and strong secrets.

9. **Redemption tokens are stored to allow the farmer to re-display their QR.** They are
   short-lived and farmer-scoped; the wholesaler lookup uses the hash. If stricter
   at-rest protection is required, encrypt the stored token or render-and-discard.

10. **Review against current OWASP Top 10 (Web + API) before go-live**, plus a
    third-party penetration test. This suite is thorough but is not a substitute for
    independent review.
