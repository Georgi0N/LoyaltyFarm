'use strict';
/** Wholesaler API: validate a redemption QR/code and confirm gift handover. */
const express = require('express');
const rateLimit = require('express-rate-limit');
const { db, audit } = require('../db');
const { requireRole, maskMobile } = require('../security');
const { lookupRedemption, confirmRedemption } = require('../services');

const router = express.Router();
router.use(requireRole('wholesaler'));

const lookupLimiter = rateLimit({ windowMs: 60 * 1000, max: 40, standardHeaders: true, legacyHeaders: false });

router.get('/summary', (req, res) => {
  const id = req.actor.id;
  const total = db.prepare(`SELECT COUNT(*) c FROM redemptions WHERE wholesaler_id=?`).get(id).c;
  const today = db.prepare(`SELECT COUNT(*) c FROM redemptions WHERE wholesaler_id=? AND date(completed_at)=date('now')`).get(id).c;
  const w = db.prepare('SELECT name, location FROM wholesalers WHERE id=?').get(id);
  res.json({ wholesaler: w, stats: { total, today } });
});

// Recent handovers by THIS wholesaler (their own history only).
router.get('/recent', (req, res) => {
  const rows = db.prepare(
    `SELECT r.code, r.points_spent, r.completed_at, f.name farmer_name, rw.name reward_name
     FROM redemptions r JOIN farmers f ON f.id=r.farmer_id JOIN rewards rw ON rw.id=r.reward_id
     WHERE r.wholesaler_id=? AND r.status='redeemed' ORDER BY r.completed_at DESC LIMIT 10`
  ).all(req.actor.id);
  res.json({ recent: rows });
});

/** Look up a redemption by scanned token or manually-typed code. */
router.post('/lookup', lookupLimiter, (req, res) => {
  const key = String(req.body.code || '').trim();
  if (!key || key.length > 64) return res.status(400).json({ error: 'invalid' });
  const r = lookupRedemption(key);
  if (!r) {
    audit({ role: 'wholesaler', id: req.actor.id, action: 'redemption_lookup_miss', detail: { key: key.slice(0, 4) + '…' },
      severity: 'warning', ip: req.ip, requestId: req.requestId });
    return res.status(404).json({ error: 'not_found' });
  }
  res.json({
    redemption: {
      id: r.id, code: r.code, status: r.status,
      farmer_name: r.farmer_name, farmer_mobile: maskMobile(r.farmer_mobile), // PII masked
      reward_name: r.reward_name, reward_name_ar: r.reward_name_ar,
      points_spent: r.points_spent, created_at: r.created_at, expires_at: r.expires_at,
      already_completed: r.status !== 'pending',
    },
  });
});

/** Confirm the gift was handed over — invalidates the code immediately. */
router.post('/confirm', (req, res) => {
  const id = Number(req.body.redemptionId);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'invalid' });
  const result = confirmRedemption(req.actor.id, id, { ip: req.ip, requestId: req.requestId });
  if (!result.ok) return res.status(409).json({ error: result.code });
  res.json({ ok: true });
});

module.exports = router;
