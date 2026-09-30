'use strict';
/** Authentication for all roles. Farmers verify by OTP; staff by password (+MFA). */
const express = require('express');
const rateLimit = require('express-rate-limit');
const { db, audit } = require('../db');
const {
  verifyPassword, hashPassword, isStrongPassword, normalizeMobile, maskMobile, cleanText,
  lockRemaining, registerLoginFailure, registerLoginSuccess,
} = require('../security');
const { verifyTotp, hashResetToken, randomId } = require('../crypto');
const otp = require('../otp');
const sessions = require('../sessions');
const { permissionsFor } = require('../rbac');
const config = require('../config');
const { sendMail } = require('../email');

const router = express.Router();

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 50, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too_many_attempts' } });
const otpSendLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too_many_requests' } });
const otpVerifyLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too_many_attempts' } });

/* ------------------------------- Session info ------------------------------- */
router.get('/me', (req, res) => {
  const u = req.session.user;
  if (!u) return res.json({ user: null });
  if (u.role === 'farmer') {
    const f = db.prepare('SELECT id, name, mobile, language, points_balance, status FROM farmers WHERE id=?').get(u.id);
    if (!f || f.status !== 'active') return req.session.destroy(() => res.json({ user: null }));
    return res.json({ user: { role: 'farmer', ...f } });
  }
  if (u.role === 'admin') {
    return res.json({ user: { role: 'admin', id: u.id, name: u.name, adminRole: u.adminRole, permissions: permissionsFor(u.adminRole) } });
  }
  return res.json({ user: u });
});

router.post('/logout', (req, res) => { sessions.destroy(req).then(() => res.json({ ok: true })); });

router.post('/logout-all', (req, res) => {
  const u = req.session.user;
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  sessions.revokeAll(u.role, u.id);
  audit({ role: u.role, id: u.id, action: 'logout_all', ip: req.ip, requestId: req.requestId });
  sessions.destroy(req).then(() => res.json({ ok: true }));
});

/* ------------------------------- Farmer OTP ------------------------------- */
router.post('/farmer/request-otp', otpSendLimiter, (req, res) => {
  const mobile = normalizeMobile(req.body.mobile);
  if (!mobile) return res.status(400).json({ error: 'invalid_mobile' });
  // Generic response regardless of whether the number is already registered
  // (prevents account enumeration).
  const result = otp.requestOtp(mobile, { ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, cooldown: result.cooldown || 0, ...(result.devCode ? { devCode: result.devCode } : {}) });
});

router.post('/farmer/verify-otp', otpVerifyLimiter, (req, res) => {
  const mobile = normalizeMobile(req.body.mobile);
  if (!mobile) return res.status(400).json({ error: 'invalid_mobile' });
  const result = otp.verifyOtp(mobile, req.body.code, { ip: req.ip, requestId: req.requestId });
  if (!result.ok) return res.status(401).json({ error: result.error });

  // Mark this session as OTP-verified for this phone (short window to finish).
  req.session.otp = { phone: mobile, at: Date.now() };

  const farmer = db.prepare('SELECT * FROM farmers WHERE mobile=?').get(mobile);
  if (farmer) {
    if (farmer.status !== 'active') return res.status(403).json({ error: 'blocked' });
    db.prepare(`UPDATE farmers SET last_ip=?, last_login_at=datetime('now') WHERE id=?`).run(req.ip, farmer.id);
    return sessions.login(req, { role: 'farmer', id: farmer.id }).then((ok) => {
      if (!ok) return res.status(500).json({ error: 'server_error' });
      // regenerate wiped session.otp; that's fine, farmer is now logged in.
      audit({ role: 'farmer', id: farmer.id, action: 'farmer_login', ip: req.ip, requestId: req.requestId });
      res.json({ user: publicFarmer(farmer) });
    });
  }
  res.json({ ok: true, needsRegistration: true, mobile: maskMobile(mobile) });
});

router.post('/farmer/register', (req, res) => {
  const v = req.session.otp;
  if (!v || Date.now() - v.at > 10 * 60 * 1000) return res.status(440).json({ error: 'otp_expired' });
  const mobile = v.phone;
  if (db.prepare('SELECT 1 FROM farmers WHERE mobile=?').get(mobile)) return res.status(409).json({ error: 'exists' });
  const name = cleanText(req.body.name, 80);
  if (!name) return res.status(400).json({ error: 'name_required' });
  const language = req.body.language === 'en' ? 'en' : 'ar';
  const info = db.prepare('INSERT INTO farmers (mobile, name, language, created_ip, last_ip, last_login_at) VALUES (?,?,?,?,?,datetime(\'now\'))')
    .run(mobile, name, language, req.ip, req.ip);
  const farmer = db.prepare('SELECT * FROM farmers WHERE id=?').get(info.lastInsertRowid);
  audit({ role: 'farmer', id: farmer.id, action: 'farmer_registered', entity: 'farmer', target: farmer.id, ip: req.ip, requestId: req.requestId });
  sessions.login(req, { role: 'farmer', id: farmer.id }).then((ok) => {
    if (!ok) return res.status(500).json({ error: 'server_error' });
    res.json({ user: publicFarmer(farmer) });
  });
});

const publicFarmer = (f) => ({ role: 'farmer', id: f.id, name: f.name, mobile: f.mobile, language: f.language, points_balance: f.points_balance });

/* ------------------------------- Wholesaler ------------------------------- */
router.post('/wholesaler', loginLimiter, (req, res) => {
  const username = cleanText(req.body.username, 40).toLowerCase();
  const w = db.prepare('SELECT * FROM wholesalers WHERE username=?').get(username);
  const remaining = lockRemaining(w);
  if (remaining) return res.status(429).json({ error: 'locked', retryAfter: remaining });
  if (!w || !verifyPassword(String(req.body.password || ''), w.password_hash)) {
    if (w) registerLoginFailure('wholesalers', w.id);
    audit({ action: 'login_failed', entity: 'wholesaler', detail: { username }, severity: 'warning', ip: req.ip, requestId: req.requestId });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  if (w.status !== 'active') return res.status(403).json({ error: 'disabled' });
  registerLoginSuccess('wholesalers', w.id);
  db.prepare(`UPDATE wholesalers SET last_login_at=datetime('now') WHERE id=?`).run(w.id);
  sessions.login(req, { role: 'wholesaler', id: w.id, name: w.name }).then(() => {
    audit({ role: 'wholesaler', id: w.id, action: 'wholesaler_login', ip: req.ip, requestId: req.requestId });
    res.json({ user: { role: 'wholesaler', id: w.id, name: w.name, location: w.location }, mustChangePassword: !!w.must_change_password });
  });
});

/* ------------------------------- Admin (+MFA) ------------------------------- */
router.post('/admin', loginLimiter, (req, res) => {
  const username = cleanText(req.body.username, 40).toLowerCase();
  const a = db.prepare('SELECT * FROM admins WHERE username=?').get(username);
  const remaining = lockRemaining(a);
  if (remaining) return res.status(429).json({ error: 'locked', retryAfter: remaining });
  if (!a || !verifyPassword(String(req.body.password || ''), a.password_hash)) {
    if (a) registerLoginFailure('admins', a.id);
    audit({ action: 'login_failed', entity: 'admin', detail: { username }, severity: 'warning', ip: req.ip, requestId: req.requestId });
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  if (a.status !== 'active') return res.status(403).json({ error: 'disabled' });

  if (a.mfa_enabled) {
    const code = String(req.body.totp || '');
    if (!code) return res.status(401).json({ error: 'mfa_required' });
    if (!verifyTotp(a.totp_secret, code)) {
      registerLoginFailure('admins', a.id);
      audit({ action: 'admin_mfa_failed', entity: 'admin', detail: { username }, severity: 'alert', ip: req.ip, requestId: req.requestId });
      return res.status(401).json({ error: 'mfa_invalid' });
    }
  }
  registerLoginSuccess('admins', a.id);
  db.prepare(`UPDATE admins SET last_login_at=datetime('now') WHERE id=?`).run(a.id);
  sessions.login(req, { role: 'admin', id: a.id, name: a.name, adminRole: a.role }).then(() => {
    audit({ role: 'admin', id: a.id, action: 'admin_login', detail: { adminRole: a.role }, ip: req.ip, requestId: req.requestId });
    res.json({ user: { role: 'admin', id: a.id, name: a.name, adminRole: a.role, permissions: permissionsFor(a.role) },
      mustChangePassword: !!a.must_change_password });
  });
});

/* ------------------------------- Change password (staff) ------------------------------- */
// Session-authenticated. Used for the forced change after a temporary password,
// and for voluntary changes. Revokes the user's OTHER sessions on success.
router.post('/change-password', (req, res) => {
  const u = req.session.user;
  if (!u || (u.role !== 'admin' && u.role !== 'wholesaler')) return res.status(401).json({ error: 'unauthorized' });
  const table = u.role === 'admin' ? 'admins' : 'wholesalers';
  const row = db.prepare(`SELECT password_hash FROM ${table} WHERE id=?`).get(u.id);
  if (!row) return res.status(401).json({ error: 'unauthorized' });
  if (!verifyPassword(String(req.body.current || ''), row.password_hash)) {
    audit({ role: u.role, id: u.id, action: 'password_change_failed', severity: 'warning', ip: req.ip, requestId: req.requestId });
    return res.status(401).json({ error: 'invalid_current' });
  }
  const next = String(req.body.next || '');
  if (!isStrongPassword(next)) return res.status(400).json({ error: 'weak_password' });
  db.prepare(`UPDATE ${table} SET password_hash=?, must_change_password=0 WHERE id=?`).run(hashPassword(next), u.id);
  sessions.revokeAllExcept(u.role, u.id, req.sessionID);
  audit({ role: u.role, id: u.id, action: 'password_changed', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

/* ------------------------------- Password reset (staff, by email) ------------------------------- */
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'too_many_requests' } });

// Request a reset link. Always returns a generic success (no account enumeration).
router.post('/forgot-password', resetLimiter, (req, res) => {
  const role = req.body.role === 'admin' ? 'admin' : (req.body.role === 'wholesaler' ? 'wholesaler' : null);
  const identifier = cleanText(req.body.identifier, 120).toLowerCase();
  const done = () => res.json({ ok: true });
  if (!role || !identifier) return done();
  const table = role === 'admin' ? 'admins' : 'wholesalers';
  const user = db.prepare(`SELECT id, name, email, username FROM ${table} WHERE lower(username)=? OR lower(email)=?`).get(identifier, identifier);
  if (!user || !user.email) { // still audit the attempt, but reveal nothing
    audit({ action: 'password_reset_requested', entity: role, detail: { found: false }, severity: 'warning', ip: req.ip, requestId: req.requestId });
    return done();
  }
  const token = randomId(32);
  const expires = new Date(Date.now() + 30 * 60000).toISOString().slice(0, 19).replace('T', ' ');
  db.prepare('INSERT INTO password_resets (role, user_id, token_hash, expires_at, created_ip) VALUES (?,?,?,?,?)')
    .run(role, user.id, hashResetToken(token), expires, req.ip);
  const base = config.APP_URL || `${req.protocol}://${req.get('host')}`;
  const link = `${base}/reset?token=${encodeURIComponent(token)}&role=${role}`;
  sendMail({
    to: user.email,
    subject: 'Reset your Hasad password',
    text: `Hello ${user.name},\n\nWe received a request to reset your Hasad ${role} password.\nOpen this link to choose a new password (valid for 30 minutes):\n\n${link}\n\nIf you did not request this, you can safely ignore this email.`,
    html: `<p>Hello ${user.name},</p><p>We received a request to reset your Hasad <b>${role}</b> password.</p>
      <p><a href="${link}" style="background:#22a65c;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:700">Reset password</a></p>
      <p style="color:#6b7d75;font-size:13px">This link is valid for 30 minutes. If you didn't request it, ignore this email.</p>`,
  });
  audit({ action: 'password_reset_requested', entity: role, target: user.id, ip: req.ip, requestId: req.requestId });
  done();
});

// Complete a reset with the emailed token + a new password.
router.post('/reset-password', resetLimiter, (req, res) => {
  const token = String(req.body.token || '');
  const next = String(req.body.next || '');
  if (!token) return res.status(400).json({ error: 'invalid_token' });
  if (!isStrongPassword(next)) return res.status(400).json({ error: 'weak_password' });
  const row = db.prepare('SELECT * FROM password_resets WHERE token_hash=? AND used=0').get(hashResetToken(token));
  if (!row) return res.status(400).json({ error: 'invalid_token' });
  if (new Date(row.expires_at.replace(' ', 'T') + 'Z').getTime() < Date.now()) return res.status(400).json({ error: 'expired' });
  const table = row.role === 'admin' ? 'admins' : 'wholesalers';
  db.prepare(`UPDATE ${table} SET password_hash=?, must_change_password=0, failed_attempts=0, locked_until=NULL WHERE id=?`)
    .run(hashPassword(next), row.user_id);
  // Consume this and any other outstanding tokens for the user; kill their sessions.
  db.prepare('UPDATE password_resets SET used=1 WHERE role=? AND user_id=?').run(row.role, row.user_id);
  sessions.revokeAll(row.role, row.user_id);
  audit({ role: row.role, id: row.user_id, action: 'password_reset_completed', severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

module.exports = router;
