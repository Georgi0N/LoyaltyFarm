'use strict';
/**
 * OTP (one-time passcode) verification for farmer registration/login.
 *
 * - Codes are random digits; only an HMAC(phone:code) is stored — never plaintext,
 *   never logged in production.
 * - Short TTL, single-use, capped verify attempts (brute-force resistant),
 *   capped sends per window, and a resend cooldown.
 * - Responses are deliberately generic to avoid phone-number enumeration.
 *
 * Delivery is pluggable. In development the code is printed to the server console
 * (and optionally echoed to the dev client). A production deployment must wire a
 * real SMS/WhatsApp provider in `deliver()` — see SECURITY.md.
 */
const crypto = require('crypto');
const { db, audit } = require('./db');
const config = require('./config');
const settings = require('./settings');
const { hashOtp, safeEqual } = require('./crypto');

function genCode(len) {
  let s = '';
  while (s.length < len) s += crypto.randomInt(0, 10);
  return s.slice(0, len);
}

function deliver(phone, code) {
  if (config.OTP_DELIVERY === 'console') {
    // Dev-only: allows manual testing without an SMS provider.
    // eslint-disable-next-line no-console
    console.log(`[otp] (dev) code for ${maskPhone(phone)} = ${code}`);
  } else {
    // eslint-disable-next-line no-console
    console.warn(`[otp] delivery provider not configured; code for ${maskPhone(phone)} was NOT sent.`);
  }
}

const maskPhone = (p) => (p ? p.replace(/^(\d{3})(\d+)(\d{2})$/, (m, a, b, c) => `${a}${'*'.repeat(b.length)}${c}`) : '');

/**
 * Issue an OTP for a phone number. Always returns a generic success shape so
 * callers cannot use it to probe which numbers exist.
 */
function requestOtp(phone, ctx = {}) {
  const ttl = settings.get('otp.ttl_sec');
  const maxSends = settings.get('otp.max_sends_per_window');
  const sendWindow = settings.get('otp.send_window_sec');
  const cooldown = settings.get('otp.resend_cooldown_sec');
  const len = settings.get('otp.length');

  const recentSends = db.prepare(
    `SELECT COUNT(*) c FROM otp_challenges WHERE phone=? AND created_at >= datetime('now', ?)`
  ).get(phone, `-${sendWindow} seconds`).c;
  if (recentSends >= maxSends) {
    audit({ action: 'otp_send_blocked', entity: 'otp', detail: { reason: 'rate_limited' }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: true, throttled: true }; // generic: do not reveal
  }

  const last = db.prepare(
    `SELECT last_sent_at FROM otp_challenges WHERE phone=? ORDER BY id DESC LIMIT 1`
  ).get(phone);
  if (last) {
    const since = (Date.now() - new Date(last.last_sent_at.replace(' ', 'T') + 'Z').getTime()) / 1000;
    if (since < cooldown) return { ok: true, cooldown: Math.ceil(cooldown - since) };
  }

  // Invalidate previous outstanding challenges for this phone (single active code).
  db.prepare(`UPDATE otp_challenges SET consumed=1 WHERE phone=? AND consumed=0`).run(phone);

  const code = genCode(len);
  const expires = new Date(Date.now() + ttl * 1000).toISOString().slice(0, 19).replace('T', ' ');
  db.prepare(
    `INSERT INTO otp_challenges (phone, code_hash, expires_at, max_attempts, created_ip)
     VALUES (?,?,?,?,?)`
  ).run(phone, hashOtp(phone, code), expires, settings.get('otp.max_verify_attempts'), ctx.ip || null);

  deliver(phone, code);
  audit({ action: 'otp_sent', entity: 'otp', detail: { phone: maskPhone(phone) }, ip: ctx.ip, requestId: ctx.requestId });

  const res = { ok: true };
  if (config.OTP_DEV_ECHO) res.devCode = code; // development convenience only
  return res;
}

/** Verify a submitted code. Returns { ok } or { ok:false, error }. Generic on failure. */
function verifyOtp(phone, code, ctx = {}) {
  if (!/^\d{4,8}$/.test(String(code || ''))) return { ok: false, error: 'invalid' };

  const ch = db.prepare(
    `SELECT * FROM otp_challenges WHERE phone=? AND consumed=0 ORDER BY id DESC LIMIT 1`
  ).get(phone);
  if (!ch) return { ok: false, error: 'invalid' };

  if (new Date(ch.expires_at.replace(' ', 'T') + 'Z').getTime() < Date.now()) {
    db.prepare(`UPDATE otp_challenges SET consumed=1 WHERE id=?`).run(ch.id);
    return { ok: false, error: 'expired' };
  }
  if (ch.attempts >= ch.max_attempts) {
    db.prepare(`UPDATE otp_challenges SET consumed=1 WHERE id=?`).run(ch.id);
    audit({ action: 'otp_brute_force_blocked', entity: 'otp', detail: { phone: maskPhone(phone) }, severity: 'alert', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, error: 'too_many_attempts' };
  }

  db.prepare(`UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?`).run(ch.id);

  if (!safeEqual(ch.code_hash, hashOtp(phone, code))) {
    audit({ action: 'otp_failed', entity: 'otp', detail: { phone: maskPhone(phone) }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, error: 'invalid' };
  }

  db.prepare(`UPDATE otp_challenges SET consumed=1 WHERE id=?`).run(ch.id);
  audit({ action: 'otp_verified', entity: 'otp', detail: { phone: maskPhone(phone) }, ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true };
}

module.exports = { requestOtp, verifyOtp, maskPhone };
