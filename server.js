'use strict';
/**
 * Hasad Loyalty — central backend / API.
 * Serves the REST API + the three static portals (farmer, wholesaler, admin).
 */
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const config = require('./src/config');
const { audit } = require('./src/db');
const { ensureCsrf, csrfProtect } = require('./src/security');
const sessions = require('./src/sessions');
const { randomId } = require('./src/crypto');

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
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
  hsts: config.IS_PROD ? { maxAge: 15552000, includeSubDomains: true } : false,
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

// Secure QR print page (HTML, browser-navigable, auth enforced inside the router).
app.use('/admin/print', require('./src/routes/print'));

// Printed QR scan URL (/c/<token>) -> farmer app deep link. Token is opaque here.
app.get('/c/:token', (req, res) => {
  const t = String(req.params.token || '').slice(0, 64);
  res.redirect('/farmer?c=' + encodeURIComponent(t));
});

// --- Static portals ---
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

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
