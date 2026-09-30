'use strict';
/**
 * Hasad Loyalty — central backend / API.
 * Serves the REST API + the three static portals (farmer, wholesaler, admin).
 */
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const config = require('./src/config');
const { audit } = require('./src/db');
const { ensureCsrf, csrfProtect } = require('./src/security');
const sessions = require('./src/sessions');
const { randomId, safeEqual } = require('./src/crypto');

const app = express();
app.set('trust proxy', config.TRUST_PROXY);
app.disable('x-powered-by');

// Force HTTPS in production (secure cookies must never travel over HTTP).
if (config.IS_PROD) {
  app.use((req, res, next) => {
    if (req.secure || req.get('x-forwarded-proto') === 'https') return next();
    return res.redirect(308, 'https://' + req.headers.host + req.originalUrl);
  });
}

// Correlation id for every request (used in logs + audit, never leaks internals).
app.use((req, res, next) => { req.requestId = randomId(8); res.setHeader('X-Request-Id', req.requestId); next(); });

// --- Security headers ---
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // NOTE: 'unsafe-inline' is required by the current inline <script>/<style>
      // blocks in the static HTML. See SECURITY.md → Known Limitations for the
      // nonce-based hardening path.
      scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://unpkg.com', "'unsafe-inline'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com', 'https://cdn.jsdelivr.net', "'unsafe-inline'"],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
      imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
      connectSrc: ["'self'"],
      mediaSrc: ["'self'", 'blob:'],
      workerSrc: ["'self'", 'blob:'],       // camera QR scanner (html5-qrcode) worker
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      // Force browsers to upgrade any http subresource to https in production.
      ...(config.IS_PROD ? { upgradeInsecureRequests: [] } : {}),
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: config.IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard: { action: 'deny' },
}));
app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), payment=()'); next(); });

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser());

app.use(session({
  name: 'hasad.sid',
  secret: config.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.COOKIE_SECURE,
    maxAge: config.SESSION_ABSOLUTE_MS,
  },
}));

// Global soft limiter (defends every route) + stricter API limiter.
app.use(rateLimit({ windowMs: 60 * 1000, max: 600, standardHeaders: true, legacyHeaders: false }));
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });

app.get('/api/csrf', (req, res) => res.json({ csrfToken: ensureCsrf(req) }));

// All mutating API calls: rate limit -> CSRF -> server-side session validity.
app.use('/api', apiLimiter, csrfProtect, sessions.validate);

app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/farmer', require('./src/routes/farmer'));
app.use('/api/wholesaler', require('./src/routes/wholesaler'));
app.use('/api/admin', require('./src/routes/admin'));

// ========================= Portal serving =========================
// Each portal is reached its own way: the customer app is at '/', partners at
// PARTNER_PATH, and the admin console at an unguessable ADMIN_PATH (optionally
// behind a shared access code). Only /assets is served statically, so the admin
// HTML can never be fetched at a guessable path.
const PUB = path.join(__dirname, 'public');
app.use('/assets', express.static(path.join(PUB, 'assets'), { maxAge: '7d' }));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(PUB, 'assets', 'img', 'logo.png')));

// Printed QR scan URL (/c/<token>) -> customer app deep link. Token is opaque here.
app.get('/c/:token', (req, res) => {
  const t = String(req.params.token || '').slice(0, 64);
  res.redirect('/?c=' + encodeURIComponent(t));
});

// --- Customer (farmer) portal at the root ---
const sendFarmer = (req, res) => res.sendFile(path.join(PUB, 'farmer', 'index.html'));
app.get('/', sendFarmer);
app.get('/app', sendFarmer);
app.get('/farmer', (req, res) => res.redirect('/'));            // legacy path -> root

// Password-reset landing (staff email links point here).
app.get('/reset', (req, res) => res.sendFile(path.join(PUB, 'reset', 'index.html')));

// --- Partner (wholesaler) portal ---
app.get(config.PARTNER_PATH, (req, res) => res.sendFile(path.join(PUB, 'wholesaler', 'index.html')));
app.get('/wholesaler', (req, res) => res.redirect(config.PARTNER_PATH)); // legacy path

// --- Admin console: unguessable path + optional access-code gate ---
function gatePage(msg) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Restricted</title><style>body{font-family:system-ui,Arial,sans-serif;background:#0a5f34;color:#fff;
  display:grid;place-items:center;min-height:100vh;margin:0}form{background:#fff;color:#10241b;padding:2rem;border-radius:16px;
  width:min(90vw,340px);box-shadow:0 24px 48px -18px rgba(0,0,0,.4)}h1{font-size:1.15rem;margin:0 0 1rem}
  input{width:100%;padding:.7rem;border:1px solid #cfe0d6;border-radius:8px;margin-bottom:.8rem;box-sizing:border-box}
  button{width:100%;padding:.7rem;border:0;border-radius:8px;background:#22a65c;color:#fff;font-weight:700;cursor:pointer}
  p{color:#e5484d;font-size:.85rem;margin:.2rem 0 .8rem}</style>
  <form method="post" action="${config.ADMIN_PATH}"><h1>🔒 Staff access</h1>
  ${msg ? `<p>${msg}</p>` : ''}
  <input type="password" name="code" placeholder="Access code" autofocus autocomplete="off">
  <button type="submit">Continue</button></form>`;
}
function adminGate(req, res, next) {
  if (!config.ADMIN_ACCESS_CODE) return next();
  if (req.session && req.session.adminGate) return next();
  const provided = (req.method === 'POST' ? (req.body && req.body.code) : req.query.k) || '';
  if (provided && safeEqual(String(provided), config.ADMIN_ACCESS_CODE)) {
    req.session.adminGate = true;
    return req.session.save(() => res.redirect(config.ADMIN_PATH));
  }
  return res.status(req.method === 'POST' ? 401 : 200).send(gatePage(req.method === 'POST' ? 'Wrong code.' : ''));
}
function serveAdmin(req, res) {
  // Inject the (secret) admin base path so the client builds print URLs correctly.
  const html = fs.readFileSync(path.join(PUB, 'admin', 'index.html'), 'utf8')
    .replace('</head>', `<script>window.__ADMIN_BASE=${JSON.stringify(config.ADMIN_PATH)};</script></head>`);
  res.type('html').send(html);
}
const adminGateLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: 'Too many attempts. Try again later.' });
app.get(config.ADMIN_PATH, adminGateLimiter, adminGate, serveAdmin);
app.post(config.ADMIN_PATH, adminGateLimiter, adminGate);
// Secure QR print page lives under the admin path (auth enforced inside the router).
app.use(config.ADMIN_PATH + '/print', adminGate, require('./src/routes/print'));

app.use((req, res) => res.status(404).json({ error: 'not_found' }));

// Central error handler: generic message to client, full detail to server log only.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(`[error] rid=${req.requestId}`, err && err.stack ? err.stack : err);
  audit({ requestId: req.requestId, action: 'server_error', entity: req.path, severity: 'alert',
    detail: { message: err && err.message }, ip: req.ip });
  res.status(500).json({ error: 'server_error', requestId: req.requestId });
});

if (require.main === module) {
  app.listen(config.PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`\n  Hasad Loyalty running:  http://localhost:${config.PORT}`);
    console.log(`  Farmer      ->  /farmer     Wholesaler ->  /wholesaler     Admin ->  /admin\n`);
  });
}

module.exports = app;
