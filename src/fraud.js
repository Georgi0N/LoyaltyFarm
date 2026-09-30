'use strict';
/**
 * Configurable fraud/risk engine.
 *
 * Computes a 0–100 risk score from behavioural signals (velocity of scans,
 * invalid-token attempts, redemption velocity, account age). Returns a band:
 *   low    -> allow
 *   medium -> allow but log + (optionally) require extra verification
 *   high   -> hold the transaction for manual admin review
 *
 * Signals are deliberately behavioural, NOT "same IP = fraud". Shared Wi-Fi /
 * carrier NAT is normal for farmers, so IP is only ever a weak secondary signal.
 */
const { db } = require('./db');
const settings = require('./settings');

const countSince = (sql, farmerId, seconds) =>
  db.prepare(sql).get(farmerId, `-${seconds} seconds`).c;

function scoreFarmer(farmerId, kind) {
  const reasons = [];
  let score = 0;

  const cv = settings.get('fraud.claim_velocity');
  const scans = countSince(
    `SELECT COUNT(*) c FROM points_transactions WHERE farmer_id=? AND type='earn' AND created_at >= datetime('now', ?)`,
    farmerId, cv.window_sec);
  if (scans >= cv.count_high) { score += cv.weight; reasons.push(`claim_velocity_high(${scans})`); }
  else if (scans >= cv.count_medium) { score += Math.round(cv.weight / 2); reasons.push(`claim_velocity_medium(${scans})`); }

  const iv = settings.get('fraud.invalid_scans');
  const invalid = countSince(
    `SELECT COUNT(*) c FROM audit_logs WHERE actor_role='farmer' AND actor_id=? AND action IN ('suspicious_scan','duplicate_scan') AND created_at >= datetime('now', ?)`,
    farmerId, iv.window_sec);
  if (invalid >= iv.count_high) { score += iv.weight; reasons.push(`invalid_scans_high(${invalid})`); }
  else if (invalid >= iv.count_medium) { score += Math.round(iv.weight / 2); reasons.push(`invalid_scans_medium(${invalid})`); }

  if (kind === 'redeem') {
    const rv = settings.get('fraud.redeem_velocity');
    const redeems = countSince(
      `SELECT COUNT(*) c FROM redemptions WHERE farmer_id=? AND created_at >= datetime('now', ?)`,
      farmerId, rv.window_sec);
    if (redeems >= rv.count_high) { score += rv.weight; reasons.push(`redeem_velocity_high(${redeems})`); }
    else if (redeems >= rv.count_medium) { score += Math.round(rv.weight / 2); reasons.push(`redeem_velocity_medium(${redeems})`); }
  }

  const newSec = settings.get('fraud.new_account_sec');
  const isNew = db.prepare(
    `SELECT (strftime('%s','now') - strftime('%s', created_at)) < ? AS n FROM farmers WHERE id=?`
  ).get(newSec, farmerId);
  if (isNew && isNew.n) { score += settings.get('fraud.new_account_weight'); reasons.push('new_account'); }

  score = Math.min(100, score);
  const bands = settings.get('fraud.risk_bands');
  const band = score >= bands.high ? 'high' : score >= bands.medium ? 'medium' : 'low';
  return { score, band, reasons };
}

/** Record a HIGH-risk hold for manual review. */
const openReview = db.prepare(
  `INSERT INTO risk_reviews (farmer_id, kind, risk_score, reasons, payload, status)
   VALUES (?,?,?,?,?, 'open')`
);
function holdForReview(farmerId, kind, risk, payload) {
  const info = openReview.run(farmerId, kind, risk.score, JSON.stringify(risk.reasons), JSON.stringify(payload || {}));
  db.prepare(`UPDATE farmers SET risk_state='high' WHERE id=?`).run(farmerId);
  return info.lastInsertRowid;
}

module.exports = { scoreFarmer, holdForReview };
