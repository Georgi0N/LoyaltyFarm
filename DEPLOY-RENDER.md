# Deploy Hasad Loyalty (Node) on Render — free

This runs the **original, unmodified** Node app on Render's free tier using the
included `render.yaml` blueprint. Render keeps a real Node process alive (unlike
Vercel), so `better-sqlite3` and the Express server work as-is.

> **Demo mode:** the free tier sleeps after ~15 min idle and its disk is
> **ephemeral**, so the SQLite database is re-seeded on every boot. Great for a
> live demo; not for durable data. To make it permanent, see the last section.

---

## 1. Put the code in a Git repo

Render deploys from GitHub/GitLab. From the project folder:

```bash
cd C:\Users\pc\farmers-loyalty
git init
git add .
git commit -m "Hasad loyalty app + Render blueprint"
git branch -M main
git remote add origin https://github.com/<you>/hasad-loyalty.git   # create this empty repo on GitHub first
git push -u origin main
```
`node_modules/`, the database, and `.env` are already git-ignored.

## 2. Create the service on Render

1. Sign in at **https://render.com** (free, GitHub login is easiest).
2. **New +  →  Blueprint**.
3. Pick your `hasad-loyalty` repo. Render reads `render.yaml` and shows one free
   web service. Click **Apply**.
4. Wait for the first build/deploy (a couple of minutes). You'll get a URL like
   `https://hasad-loyalty.onrender.com`.

That's it — no env vars to set by hand; the blueprint supplies them.

## 3. Use it — each portal has its own address

The three portals are **separated** and reached different ways:

- **Customer (farmer) app** → `/` (the root) — pick your **country**, enter a mobile
  number (fully international now); the **OTP is shown on screen** in demo mode, so
  you can sign in without SMS. Scan/enter a demo QR token to earn points and redeem.
- **Partner (wholesaler) portal** → `/partner` — `baghdad / Wholesale@123`
  (also `basra`, `mosul`). Confirm farmer redemptions.
- **Admin console** → **`/admin-console`** — `admin / admin123` (also
  `manager / Manager@123`, `viewer / Viewer@123`). This path is intentionally
  **not linked anywhere** and `/admin` returns 404. Change `ADMIN_PATH` in
  `render.yaml` to your own unguessable slug, and optionally set `ADMIN_ACCESS_CODE`
  (an env var) to require a shared code before the admin login even appears.

**Forgot password?** The staff logins (partner + admin) have a “Forgot password?”
link that emails a reset link. Without SMTP configured it isn't sent — the reset
link is written to the **server logs** (Render → your service → *Logs*), so you can
still complete a reset in the demo. To send real email, add `SMTP_HOST`, `SMTP_USER`,
`SMTP_PASS`, `EMAIL_FROM` env vars (any provider: Gmail app-password, SendGrid,
Resend, Mailgun, SES) — no code change needed.

> First request after it's been idle takes ~30–50 s while the free instance wakes.

## 4. Notes & limits (free tier)

- **Data resets** on every deploy, restart, or wake-from-sleep (ephemeral disk +
  boot re-seed). Anything testers create is temporary.
- Demo mode uses the app's built-in fallback secrets and shows OTP codes on
  screen — fine for a public demo, **not** for real farmer data.

## 5. Make it durable / production-ready

Two changes turn this into a real deployment:

1. **Persistent database.** On Render this means a **paid** persistent disk
   mounted at `/opt/render/project/src/data` (so `data/app.db` survives), or
   switching to a hosted DB. If you want *free* durability instead, deploy the
   same repo on an **Oracle Cloud Always Free VM** using `DEPLOYMENT.md` (real
   disk, always-on) — the app needs no code changes there.
2. **Production hardening.** Set `APP_ENV=production` and add strong unique
   secrets (`SESSION_SECRET`, `QR_HMAC_SECRET`, `OTP_HMAC_SECRET`,
   `REDEMPTION_HMAC_SECRET`, `QR_ENC_SECRET`), `COOKIE_SECURE=true`,
   `OTP_DEV_ECHO=false`, and remove the `node src/seed.js` part of the start
   command (create your admin once with `npm run create-super-admin`). In
   production you must also wire a real SMS/WhatsApp OTP provider in `src/otp.js`,
   otherwise farmers can't receive login codes. Full checklist in `DEPLOYMENT.md`.
