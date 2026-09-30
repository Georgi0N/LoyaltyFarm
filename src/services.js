'use strict';
/**
 * Core business logic — the security boundary. The frontend sends only tokens
 * and identifiers; EVERYTHING that matters (point values, balances, eligibility,
 * statuses, prices) is decided here against the database.
 *
 * Every points-changing operation is a single better-sqlite3 transaction with
 * conditional UPDATEs, so concurrent claims/redemptions cannot double-spend.
 * The points ledger is append-only (enforced by DB triggers).
 */
const { db, audit } = require('./db');
const settings = require('./settings');
const fraud = require('./fraud');
const {
  qrToken, redemptionToken, redemptionCode, hashQrToken, hashRedemptionToken, encryptToken,
} = require('./crypto');

/* ------------------------------- Ledger helper ------------------------------- */
const insertLedger = db.prepare(
  `INSERT INTO points_transactions
     (farmer_id, type, source, points, prev_balance, balance_after, qr_id, redemption_id, reference, description, created_by_role, created_by_id)
   VALUES (@farmer_id,@type,@source,@points,@prev,@after,@qr_id,@redemption_id,@reference,@description,@by_role,@by_id)`
);
const getFarmer = db.prepare('SELECT * FROM farmers WHERE id=?');

/** Post a ledger entry AND move the cached balance atomically (caller in a txn). */
function post(farmerId, { type, source, points, qr_id = null, redemption_id = null, reference = null, description = null, by_role = 'system', by_id = null }) {
  const before = getFarmer.get(farmerId).points_balance;
  const after = before + points; // CHECK(balance_after>=0) guards against overspend
  db.prepare('UPDATE farmers SET points_balance=? WHERE id=?').run(after, farmerId);
  insertLedger.run({ farmer_id: farmerId, type, source, points, prev: before, after, qr_id, redemption_id, reference, description, by_role, by_id });
  return after;
}

/* ------------------------- Bulk secure QR generation ------------------------- */
const insertQr = db.prepare(
  `INSERT INTO product_qr_codes (token_hash, token_enc, batch_id, sku_id, product_id, point_value, status)
   VALUES (?,?,?,?,?,?, 'unused')`
);
const bumpBatchCount = db.prepare('UPDATE batches SET qr_count = qr_count + ? WHERE id=?');
const skuProductId = db.prepare('SELECT product_id FROM skus WHERE id=?');

/**
 * Generate `count` unique QR tokens for a batch. Only the HMAC of each token is
 * stored; the raw tokens are returned ONCE (for label printing) and never persisted.
 */
const generateQrBatch = db.transaction((batch, count) => {
  const productId = batch.product_id || skuProductId.get(batch.sku_id).product_id;
  const tokens = [];
  for (let i = 0; i < count; i++) {
    for (let tries = 0; tries < 5; tries++) {
      const token = qrToken();
      try {
        insertQr.run(hashQrToken(token), encryptToken(token), batch.id, batch.sku_id, productId, batch.point_value);
        tokens.push(token);
        break;
      } catch (e) { if (!/UNIQUE/.test(e.message)) throw e; }
    }
  }
  bumpBatchCount.run(tokens.length, batch.id);
  return tokens;
});

/* ------------------------- Farmer claims a product QR ------------------------- */
const getQrByHash = db.prepare(
  `SELECT q.*, b.status AS batch_status, s.status AS sku_status, p.status AS product_status
   FROM product_qr_codes q JOIN batches b ON b.id=q.batch_id JOIN skus s ON s.id=q.sku_id JOIN products p ON p.id=q.product_id
   WHERE q.token_hash=?`
);
const markQrUsed = db.prepare(
  `UPDATE product_qr_codes SET status='used', claimed_by=?, claimed_at=datetime('now') WHERE id=? AND status='unused'`
);

/**
 * Claim a scanned QR. The point value comes from the DB record, never the client.
 * Returns a structured result; invalid/blocked/used codes are rejected + audited.
 * High fraud risk consumes the code but HOLDS the points for manual review.
 */
const claimQr = db.transaction((farmerId, rawToken, ctx = {}) => {
  const qr = getQrByHash.get(hashQrToken(rawToken));

  if (!qr) {
    audit({ role: 'farmer', id: farmerId, action: 'suspicious_scan', entity: 'qr',
      detail: { reason: 'invalid_token' }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'invalid' };
  }
  if (qr.status === 'blocked') {
    audit({ role: 'farmer', id: farmerId, action: 'suspicious_scan', entity: 'qr', target: qr.id,
      detail: { reason: 'blocked' }, severity: 'alert', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'blocked' };
  }
  if (qr.status === 'used') {
    audit({ role: 'farmer', id: farmerId, action: 'duplicate_scan', entity: 'qr', target: qr.id,
      detail: { reason: 'already_used', first_claimed_by: qr.claimed_by }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'used' };
  }
  if (qr.batch_status !== 'active' || qr.sku_status !== 'active' || qr.product_status !== 'active') {
    audit({ role: 'farmer', id: farmerId, action: 'ineligible_scan', entity: 'qr', target: qr.id,
      detail: { batch: qr.batch_status, sku: qr.sku_status, product: qr.product_status }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'ineligible' };
  }

  // Atomically consume the code (first claim wins; a lost race yields 0 changes).
  if (markQrUsed.run(farmerId, qr.id).changes !== 1) return { ok: false, code: 'used' };

  const risk = fraud.scoreFarmer(farmerId, 'claim');
  if (risk.band === 'high') {
    const reviewId = fraud.holdForReview(farmerId, 'claim', risk, { qr_id: qr.id, points: qr.point_value });
    audit({ role: 'farmer', id: farmerId, action: 'claim_held_review', entity: 'qr', target: qr.id,
      detail: { risk: risk.score, reasons: risk.reasons, review_id: reviewId }, severity: 'alert', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: true, held: true, points: qr.point_value, balance: getFarmer.get(farmerId).points_balance, risk: risk.band };
  }

  const balance = post(farmerId, { type: 'earn', source: 'PRODUCT_PURCHASE', points: qr.point_value,
    qr_id: qr.id, description: 'Product scan', by_role: 'farmer', by_id: farmerId });
  audit({ role: 'farmer', id: farmerId, action: 'scan_claimed', entity: 'qr', target: qr.id,
    detail: { points: qr.point_value, risk: risk.band }, severity: risk.band === 'medium' ? 'warning' : 'info', ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true, points: qr.point_value, balance, risk: risk.band };
});

/* ------------------------- Reward redemption ------------------------- */
const getReward = db.prepare('SELECT * FROM rewards WHERE id=?');
const deductStock = db.prepare('UPDATE rewards SET quantity = quantity - 1 WHERE id=? AND quantity > 0');
const insertRedemption = db.prepare(
  `INSERT INTO redemptions (code, token, token_hash, farmer_id, reward_id, points_spent, status, expires_at)
   VALUES (?,?,?,?,?,?, 'pending', ?)`
);

/** Farmer redeems a reward: validate + deduct points/stock + mint a secure token. */
const redeemReward = db.transaction((farmerId, rewardId, ctx = {}) => {
  const reward = getReward.get(rewardId);
  if (!reward || reward.status !== 'active') return { ok: false, code: 'unavailable' };
  if (reward.quantity <= 0) return { ok: false, code: 'out_of_stock' };

  const farmer = getFarmer.get(farmerId);
  if (farmer.points_balance < reward.points_required) return { ok: false, code: 'insufficient' };

  const risk = fraud.scoreFarmer(farmerId, 'redeem');
  if (risk.band === 'high') {
    const reviewId = fraud.holdForReview(farmerId, 'redeem', risk, { reward_id: rewardId, points: reward.points_required });
    audit({ role: 'farmer', id: farmerId, action: 'redeem_held_review', entity: 'reward', target: rewardId,
      detail: { risk: risk.score, reasons: risk.reasons, review_id: reviewId }, severity: 'alert', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'review' }; // no points touched
  }

  // Reserve stock first; if it lost a race, the whole txn rolls back.
  if (deductStock.run(rewardId).changes !== 1) return { ok: false, code: 'out_of_stock' };

  const code = redemptionCode();
  const token = redemptionToken();
  const ttlDays = settings.get('redemption.ttl_days');
  const expires = new Date(Date.now() + ttlDays * 86400000).toISOString().slice(0, 19).replace('T', ' ');
  const info = insertRedemption.run(code, token, hashRedemptionToken(token), farmerId, rewardId, reward.points_required, expires);

  const balance = post(farmerId, { type: 'redeem', source: 'REWARD_REDEMPTION', points: -reward.points_required,
    redemption_id: info.lastInsertRowid, description: `Redeemed: ${reward.name}`, by_role: 'farmer', by_id: farmerId });
  audit({ role: 'farmer', id: farmerId, action: 'reward_redeemed', entity: 'redemption', target: info.lastInsertRowid,
    detail: { reward_id: rewardId, points: reward.points_required }, ip: ctx.ip, requestId: ctx.requestId });

  return { ok: true, redemptionId: info.lastInsertRowid, code, token, balance, expiresAt: expires };
});

/* ------------------------- Wholesaler confirms handover ------------------------- */
const findRedemption = db.prepare(
  `SELECT r.*, f.name AS farmer_name, f.mobile AS farmer_mobile,
          rw.name AS reward_name, rw.name_ar AS reward_name_ar, rw.image AS reward_image
   FROM redemptions r JOIN farmers f ON f.id=r.farmer_id JOIN rewards rw ON rw.id=r.reward_id
   WHERE r.token_hash=? OR r.code=?`
);
const expireIfDue = db.prepare(
  `UPDATE redemptions SET status='expired' WHERE id=? AND status='pending' AND expires_at IS NOT NULL AND expires_at <= datetime('now')`
);
const completeRedemption = db.prepare(
  `UPDATE redemptions SET status='redeemed', wholesaler_id=?, completed_at=datetime('now')
   WHERE id=? AND status='pending' AND (expires_at IS NULL OR expires_at > datetime('now'))`
);

/** Look up by scanned secret (hashed) OR manually-typed code. Lazily expires. */
function lookupRedemption(codeOrToken) {
  const key = String(codeOrToken || '').toUpperCase().trim();
  let r = findRedemption.get(hashRedemptionToken(key), key);
  if (r && r.status === 'pending') { expireIfDue.run(r.id); r = findRedemption.get(hashRedemptionToken(key), key); }
  return r;
}

/** Confirm handover atomically. Second attempt (or expired code) fails. */
const confirmRedemption = db.transaction((wholesalerId, redemptionId, ctx = {}) => {
  if (completeRedemption.run(wholesalerId, redemptionId).changes !== 1) {
    audit({ role: 'wholesaler', id: wholesalerId, action: 'redemption_confirm_rejected', entity: 'redemption', target: redemptionId,
      severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
    return { ok: false, code: 'not_pending' };
  }
  audit({ role: 'wholesaler', id: wholesalerId, action: 'redemption_completed', entity: 'redemption', target: redemptionId,
    result: 'ok', ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true };
});

/* ------------------------- Admin: reviews, refunds, adjustments ------------------------- */
const getReview = db.prepare('SELECT * FROM risk_reviews WHERE id=?');

/** Approve a held claim (credit the withheld points) or held redeem (just clears). */
const approveReview = db.transaction((adminId, reviewId, ctx = {}) => {
  const rev = getReview.get(reviewId);
  if (!rev || rev.status !== 'open') return { ok: false, code: 'not_open' };
  const payload = JSON.parse(rev.payload || '{}');
  if (rev.kind === 'claim' && payload.points) {
    post(rev.farmer_id, { type: 'earn', source: 'PRODUCT_PURCHASE', points: payload.points,
      qr_id: payload.qr_id || null, reference: `review:${reviewId}`, description: 'Product scan (approved after review)',
      by_role: 'admin', by_id: adminId });
  }
  db.prepare(`UPDATE risk_reviews SET status='approved', resolved_by=?, resolved_at=datetime('now') WHERE id=?`).run(adminId, reviewId);
  db.prepare(`UPDATE farmers SET risk_state='low' WHERE id=?`).run(rev.farmer_id);
  audit({ role: 'admin', id: adminId, action: 'review_approved', entity: 'risk_review', target: reviewId, ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true };
});

const rejectReview = db.transaction((adminId, reviewId, ctx = {}) => {
  const rev = getReview.get(reviewId);
  if (!rev || rev.status !== 'open') return { ok: false, code: 'not_open' };
  db.prepare(`UPDATE risk_reviews SET status='rejected', resolved_by=?, resolved_at=datetime('now') WHERE id=?`).run(adminId, reviewId);
  audit({ role: 'admin', id: adminId, action: 'review_rejected', entity: 'risk_review', target: reviewId,
    severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true };
});

/** Admin manual point adjustment — always creates an auditable ledger entry. */
const adjustPoints = db.transaction((adminId, farmerId, delta, reason, ctx = {}) => {
  const farmer = getFarmer.get(farmerId);
  if (!farmer) return { ok: false, code: 'not_found' };
  if (farmer.points_balance + delta < 0) return { ok: false, code: 'would_go_negative' };
  const balance = post(farmerId, { type: 'adjust', source: 'ADMIN_ADJUSTMENT', points: delta,
    reference: reason, description: `Admin adjustment: ${reason}`, by_role: 'admin', by_id: adminId });
  audit({ role: 'admin', id: adminId, action: 'points_adjusted', entity: 'farmer', target: farmerId,
    detail: { delta, reason, new_balance: balance }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true, balance };
});

/** Admin cancels a pending/expired redemption and refunds the points via the ledger. */
const cancelRedemption = db.transaction((adminId, redemptionId, reason, ctx = {}) => {
  const r = db.prepare('SELECT * FROM redemptions WHERE id=?').get(redemptionId);
  if (!r || (r.status !== 'pending' && r.status !== 'expired')) return { ok: false, code: 'not_cancellable' };
  db.prepare(`UPDATE redemptions SET status='cancelled', cancel_reason=? WHERE id=?`).run(reason || 'admin_cancel', redemptionId);
  db.prepare('UPDATE rewards SET quantity = quantity + 1 WHERE id=?').run(r.reward_id);
  const balance = post(r.farmer_id, { type: 'refund', source: 'REFUND', points: r.points_spent,
    redemption_id: r.id, reference: reason, description: 'Redemption cancelled — points refunded', by_role: 'admin', by_id: adminId });
  audit({ role: 'admin', id: adminId, action: 'redemption_cancelled', entity: 'redemption', target: redemptionId,
    detail: { refund: r.points_spent, reason }, severity: 'warning', ip: ctx.ip, requestId: ctx.requestId });
  return { ok: true, balance };
});

module.exports = {
  generateQrBatch, claimQr, redeemReward,
  lookupRedemption, confirmRedemption,
  approveReview, rejectReview, adjustPoints, cancelRedemption,
};
