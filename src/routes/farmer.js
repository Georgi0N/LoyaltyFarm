'use strict';
/** Farmer API: wallet, scan-to-earn, rewards catalogue, redemption. */
const express = require('express');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');
const { db } = require('../db');
const { requireRole, isPositiveInt, idempotencyKey } = require('../security');
const { withIdempotency } = require('../idempotency');
const { claimQr, redeemReward } = require('../services');

const router = express.Router();
router.use(requireRole('farmer'));

// Per-FARMER limits (keyed by session identity, not IP) so shared Wi-Fi / carrier
// NAT never causes one farmer's activity to throttle another's.
const perFarmer = (req) => (req.session && req.session.user ? 'f' + req.session.user.id : req.ip);
const scanLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, keyGenerator: perFarmer, standardHeaders: true, legacyHeaders: false });
const redeemLimiter = rateLimit({ windowMs: 60 * 1000, max: 15, keyGenerator: perFarmer, standardHeaders: true, legacyHeaders: false });

const me = (req) => req.actor.id;

/* --------------------------------- Dashboard --------------------------------- */
router.get('/dashboard', (req, res) => {
  const f = db.prepare('SELECT id, name, mobile, language, points_balance FROM farmers WHERE id=?').get(me(req));
  const scans = db.prepare(`SELECT COUNT(*) c FROM points_transactions WHERE farmer_id=? AND type='earn'`).get(f.id).c;
  const redemptions = db.prepare(`SELECT COUNT(*) c FROM redemptions WHERE farmer_id=?`).get(f.id).c;
  res.json({ farmer: f, stats: { scans, redemptions } });
});

router.get('/transactions', (req, res) => {
  const rows = db.prepare(
    `SELECT id, type, source, points, balance_after, description, created_at
     FROM points_transactions WHERE farmer_id=? ORDER BY id DESC LIMIT 100`
  ).all(me(req));
  res.json({ transactions: rows });
});

/* ----------------------------------- Scan ----------------------------------- */
router.post('/scan', scanLimiter, (req, res) => {
  const token = String(req.body.token || '').trim();
  if (!token || token.length > 64) return res.status(400).json({ error: 'invalid' });
  const { result } = withIdempotency(
    { scope: 'claim', role: 'farmer', id: me(req), key: idempotencyKey(req) },
    () => claimQr(me(req), token, { ip: req.ip, requestId: req.requestId })
  );
  if (!result.ok) return res.status(409).json({ error: result.code });
  res.json(result); // may include { held:true } when withheld for review
});

/* --------------------------------- Rewards --------------------------------- */
router.get('/rewards', (req, res) => {
  const f = db.prepare('SELECT points_balance FROM farmers WHERE id=?').get(me(req));
  const rewards = db.prepare(
    `SELECT id, name, name_ar, description, description_ar, image, points_required, quantity
     FROM rewards WHERE status='active' ORDER BY points_required ASC`
  ).all();
  res.json({ balance: f.points_balance, rewards });
});

router.post('/redeem', redeemLimiter, (req, res) => {
  if (!isPositiveInt(req.body.rewardId)) return res.status(400).json({ error: 'invalid' });
  const { result } = withIdempotency(
    { scope: 'redeem', role: 'farmer', id: me(req), key: idempotencyKey(req) },
    () => redeemReward(me(req), Number(req.body.rewardId), { ip: req.ip, requestId: req.requestId })
  );
  if (!result.ok) return res.status(409).json({ error: result.code });
  res.json(result);
});

/* ------------------------- My redemptions (with QR) ------------------------- */
router.get('/redemptions', async (req, res) => {
  const rows = db.prepare(
    `SELECT r.id, r.code, r.token, r.status, r.points_spent, r.created_at, r.completed_at, r.expires_at,
            rw.name AS reward_name, rw.name_ar AS reward_name_ar, rw.image AS reward_image
     FROM redemptions r JOIN rewards rw ON rw.id=r.reward_id
     WHERE r.farmer_id=? ORDER BY r.id DESC`
  ).all(me(req));
  for (const r of rows) {
    if (r.status === 'pending') {
      r.qr = await QRCode.toDataURL(r.token, { margin: 1, width: 320, color: { dark: '#0E7A43', light: '#ffffff' } });
    }
    delete r.token; // never expose the raw secret beyond the rendered QR image
  }
  res.json({ redemptions: rows });
});

module.exports = router;
