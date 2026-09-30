'use strict';
/** Admin-configurable settings (fraud thresholds, OTP policy, lockout, TTLs). */
const { db } = require('./db');

const DEFAULTS = {
  'fraud.risk_bands': { medium: 30, high: 70 },
  // Points per signal, evaluated over a rolling window.
  'fraud.claim_velocity': { window_sec: 300, count_medium: 15, count_high: 40, weight: 40 },
  'fraud.invalid_scans': { window_sec: 600, count_medium: 5, count_high: 15, weight: 45 },
  'fraud.redeem_velocity': { window_sec: 3600, count_medium: 3, count_high: 6, weight: 35 },
  'fraud.new_account_sec': 120, // extra weight if account is brand new
  'fraud.new_account_weight': 15,

  'otp.ttl_sec': 300,
  'otp.length': 6,
  'otp.max_verify_attempts': 5,
  'otp.max_sends_per_window': 5,
  'otp.send_window_sec': 3600,
  'otp.resend_cooldown_sec': 45,

  'lockout.max_failed': 5,
  'lockout.lock_minutes': 15,

  'redemption.ttl_days': 30,
};

const getRow = db.prepare('SELECT value FROM settings WHERE key=?');
const upsert = db.prepare(
  `INSERT INTO settings (key, value, updated_at) VALUES (?,?,datetime('now'))
   ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`
);

function get(key) {
  const row = getRow.get(key);
  if (row) { try { return JSON.parse(row.value); } catch { return row.value; } }
  return DEFAULTS[key];
}

function set(key, value) { upsert.run(key, JSON.stringify(value)); return value; }

function all() {
  const merged = { ...DEFAULTS };
  for (const r of db.prepare('SELECT key, value FROM settings').all()) {
    try { merged[r.key] = JSON.parse(r.value); } catch { merged[r.key] = r.value; }
  }
  return merged;
}

module.exports = { get, set, all, DEFAULTS };
