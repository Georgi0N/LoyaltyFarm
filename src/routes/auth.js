'use strict';
/** Authentication for all roles. Farmers verify by OTP; staff by password (+MFA). */
const express = require('express');
const rateLimit = require('express-rate-limit');
const { db, audit } = require('../db');
const {
  verifyPassword, hashPassword, isStrongPassword, normalizeMobile, maskMobile, cleanText,
  lockRemaining, registerLoginFailure, registerLoginSuccess,
} = require('../security');
const { verifyTotp } = require('../crypto');
const otp = require('../otp');
const sessions = require('../sessions');
const { permissionsFor } = require('../rbac');

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

module.exports = router;
