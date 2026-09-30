'use strict';
/** Admin API: program management, QR generation, reporting, fraud reviews, audit. */
const express = require('express');
const { db, audit } = require('../db');
const config = require('../config');
const {
  requireRole, cleanText, isPositiveInt, intInRange, isStrongPassword,
} = require('../security');
const { requirePermission, STAFF_ROLES, permissionsFor } = require('../rbac');
const settings = require('../settings');
const sessions = require('../sessions');
const { generateTotpSecret, verifyTotp, totpUri, hashPassword, verifyPassword, tempPassword } = require('../crypto');
const {
  generateQrBatch, approveReview, rejectReview, adjustPoints, cancelRedemption,
} = require('../services');
const qrx = require('../qrexport');

// base URL used inside printed QR codes (production: set APP_URL)
const baseUrl = (req) => config.APP_URL || `${req.protocol}://${req.get('host')}`;

// Parse pagination params: page size clamped 1..100, default 25.
function paging(req) {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 25));
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
  return { limit, offset };
}

const router = express.Router();
router.use(requireRole('admin')); // verifies session + active status, sets req.actor

/* ------------------------------- CSV helpers ------------------------------- */
// Neutralise CSV/Excel formula injection: a cell starting with = + - @ (or tab/CR)
// is prefixed with a single quote so spreadsheets treat it as text.
function csvCell(v) {
  let s = String(v == null ? '' : v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return `"${s.replace(/"/g, '""')}"`;
}
function toCSV(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  return [cols.join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\r\n');
}
function sendCSV(res, filename, rows) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send('﻿' + toCSV(rows));
}

/* ================================ DASHBOARD ================================ */
router.get('/dashboard', requirePermission('dashboard.view'), (req, res) => {
  const one = (sql, ...p) => db.prepare(sql).get(...p);
  const stats = {
    farmers: one(`SELECT COUNT(*) c FROM farmers`).c,
    activeFarmers: one(`SELECT COUNT(DISTINCT farmer_id) c FROM points_transactions WHERE created_at >= datetime('now','-30 day')`).c,
    scans: one(`SELECT COUNT(*) c FROM points_transactions WHERE type='earn'`).c,
    pointsIssued: one(`SELECT COALESCE(SUM(points),0) s FROM points_transactions WHERE type='earn'`).s,
    rewardsRedeemed: one(`SELECT COUNT(*) c FROM redemptions`).c,
    qrActive: one(`SELECT COUNT(*) c FROM product_qr_codes WHERE status='unused'`).c,
    qrUsed: one(`SELECT COUNT(*) c FROM product_qr_codes WHERE status='used'`).c,
    qrTotal: one(`SELECT COUNT(*) c FROM product_qr_codes`).c,
    suspicious: one(`SELECT COUNT(*) c FROM audit_logs WHERE action IN ('suspicious_scan','duplicate_scan','ineligible_scan','csrf_rejected','login_failed','admin_mfa_failed','otp_failed','otp_brute_force_blocked','permission_denied')`).c,
    openReviews: one(`SELECT COUNT(*) c FROM risk_reviews WHERE status='open'`).c,
  };
  const scansByDay = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM points_transactions WHERE type='earn' AND created_at >= datetime('now','-14 day') GROUP BY d ORDER BY d`).all();
  const regsByDay = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM farmers WHERE created_at >= datetime('now','-14 day') GROUP BY d ORDER BY d`).all();
  const topProducts = db.prepare(`SELECT p.name, COUNT(*) c FROM points_transactions t JOIN product_qr_codes q ON q.id=t.qr_id JOIN products p ON p.id=q.product_id WHERE t.type='earn' GROUP BY p.id ORDER BY c DESC LIMIT 5`).all();
  const topRewards = db.prepare(`SELECT rw.name, COUNT(*) c FROM redemptions r JOIN rewards rw ON rw.id=r.reward_id GROUP BY rw.id ORDER BY c DESC LIMIT 5`).all();
  res.json({ stats, charts: { scansByDay, regsByDay, topProducts, topRewards } });
});

/* ================================ FARMERS ================================ */
router.get('/farmers', requirePermission('farmers.view'), (req, res) => {
  const q = cleanText(req.query.q, 40);
  const { limit, offset } = paging(req);
  const where = q ? `WHERE name LIKE @like OR mobile LIKE @like` : '';
  const params = q ? { like: `%${q}%` } : {};
  const total = db.prepare(`SELECT COUNT(*) c FROM farmers ${where}`).get(params).c;
  const rows = db.prepare(
    `SELECT id, name, mobile, language, points_balance, status, risk_state, created_at,
       (SELECT COUNT(*) FROM redemptions WHERE farmer_id=farmers.id) redemptions
     FROM farmers ${where} ORDER BY id DESC LIMIT @limit OFFSET @offset`
  ).all({ ...params, limit, offset });
  res.json({ farmers: rows, total, limit, offset });
});

router.get('/farmers/:id', requirePermission('farmers.view'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const f = db.prepare('SELECT * FROM farmers WHERE id=?').get(req.params.id);
  if (!f) return res.status(404).json({ error: 'not_found' });
  const transactions = db.prepare(`SELECT type, source, points, prev_balance, balance_after, description, created_by_role, created_at FROM points_transactions WHERE farmer_id=? ORDER BY id DESC LIMIT 100`).all(f.id);
  const redemptions = db.prepare(`SELECT r.code, r.status, r.points_spent, r.created_at, rw.name reward_name FROM redemptions r JOIN rewards rw ON rw.id=r.reward_id WHERE r.farmer_id=? ORDER BY r.id DESC`).all(f.id);
  res.json({ farmer: f, transactions, redemptions });
});

router.post('/farmers/:id/status', requirePermission('farmers.block'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const status = req.body.status === 'blocked' ? 'blocked' : 'active';
  db.prepare('UPDATE farmers SET status=? WHERE id=?').run(status, req.params.id);
  audit({ role: 'admin', id: req.actor.id, action: 'farmer_status_change', entity: 'farmer', target: Number(req.params.id),
    detail: { status }, severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, status });
});

router.post('/farmers/:id/adjust', requirePermission('farmers.adjust'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const delta = parseInt(req.body.delta, 10);
  const reason = cleanText(req.body.reason, 120);
  if (!Number.isInteger(delta) || delta === 0 || Math.abs(delta) > 1000000) return res.status(400).json({ error: 'invalid_delta' });
  if (!reason) return res.status(400).json({ error: 'reason_required' });
  const r = adjustPoints(req.actor.id, Number(req.params.id), delta, reason, { ip: req.ip, requestId: req.requestId });
  if (!r.ok) return res.status(409).json({ error: r.code });
  res.json({ ok: true, balance: r.balance });
});

/* ================================ PRODUCTS / SKUS ================================ */
router.get('/products', requirePermission('products.manage'), (req, res) => {
  res.json({ products: db.prepare(`SELECT * FROM products ORDER BY id DESC`).all(), skus: db.prepare(`SELECT * FROM skus ORDER BY id DESC`).all() });
});

router.post('/products', requirePermission('products.manage'), (req, res) => {
  const name = cleanText(req.body.name, 80);
  if (!name) return res.status(400).json({ error: 'name_required' });
  const info = db.prepare('INSERT INTO products (name, category) VALUES (?,?)').run(name, cleanText(req.body.category, 40));
  audit({ role: 'admin', id: req.actor.id, action: 'product_create', entity: 'product', target: info.lastInsertRowid, ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, id: info.lastInsertRowid });
});

router.post('/products/:id/status', requirePermission('products.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const status = req.body.status === 'inactive' ? 'inactive' : 'active';
  db.prepare('UPDATE products SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true, status });
});

router.post('/skus', requirePermission('products.manage'), (req, res) => {
  if (!isPositiveInt(req.body.productId)) return res.status(400).json({ error: 'product_required' });
  const sku_code = cleanText(req.body.skuCode, 40);
  const points = intInRange(req.body.defaultPoints, 0, 100000);
  if (!sku_code) return res.status(400).json({ error: 'sku_required' });
  if (points === null) return res.status(400).json({ error: 'invalid_points' });
  try {
    const info = db.prepare('INSERT INTO skus (product_id, sku_code, size_label, default_points) VALUES (?,?,?,?)')
      .run(req.body.productId, sku_code, cleanText(req.body.sizeLabel, 40), points);
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) { if (/UNIQUE/.test(e.message)) return res.status(409).json({ error: 'sku_exists' }); throw e; }
});

/* ================================ BATCHES ================================ */
router.get('/batches', requirePermission('batches.manage'), (req, res) => {
  const rows = db.prepare(
    `SELECT b.*, s.sku_code, p.name product_name,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='used') used,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='unused') unused
     FROM batches b JOIN skus s ON s.id=b.sku_id JOIN products p ON p.id=s.product_id ORDER BY b.id DESC`
  ).all();
  res.json({ batches: rows });
});

router.post('/batches', requirePermission('batches.manage'), (req, res) => {
  if (!isPositiveInt(req.body.skuId)) return res.status(400).json({ error: 'sku_required' });
  const sku = db.prepare('SELECT * FROM skus WHERE id=?').get(req.body.skuId);
  if (!sku) return res.status(404).json({ error: 'sku_not_found' });
  const batch_number = cleanText(req.body.batchNumber, 40);
  if (!batch_number) return res.status(400).json({ error: 'batch_number_required' });
  const pv = intInRange(req.body.pointValue, 0, 100000);
  const point_value = pv === null ? sku.default_points : pv;
  try {
    const info = db.prepare(`INSERT INTO batches (sku_id, batch_number, production_date, expiry_date, point_value) VALUES (?,?,?,?,?)`)
      .run(sku.id, batch_number, cleanText(req.body.productionDate, 20), cleanText(req.body.expiryDate, 20), point_value);
    audit({ role: 'admin', id: req.actor.id, action: 'batch_create', entity: 'batch', target: info.lastInsertRowid, ip: req.ip, requestId: req.requestId });
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) { if (/UNIQUE/.test(e.message)) return res.status(409).json({ error: 'batch_exists' }); throw e; }
});

/* ================================ QR MANAGEMENT ================================ */
router.get('/qr', requirePermission('qr.view'), (req, res) => {
  const status = ['unused', 'used', 'blocked'].includes(req.query.status) ? req.query.status : null;
  const batchId = isPositiveInt(req.query.batchId) ? Number(req.query.batchId) : null;
  const clauses = []; const params = {};
  if (status) { clauses.push('q.status=@status'); params.status = status; }
  if (batchId) { clauses.push('q.batch_id=@batchId'); params.batchId = batchId; }
  const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const { limit, offset } = paging(req);
  const total = db.prepare(`SELECT COUNT(*) c FROM product_qr_codes q ${where}`).get(params).c;
  const rows = db.prepare(
    `SELECT q.id, q.token_hash, q.status, q.point_value, q.claimed_at, b.batch_number, s.sku_code, p.name product_name
     FROM product_qr_codes q JOIN batches b ON b.id=q.batch_id JOIN skus s ON s.id=q.sku_id JOIN products p ON p.id=q.product_id
     ${where} ORDER BY q.id DESC LIMIT @limit OFFSET @offset`
  ).all({ ...params, limit, offset });
  // Only a short hash prefix is ever shown — the usable token is never stored/returned.
  for (const r of rows) { r.token_ref = r.token_hash.slice(0, 12).toUpperCase(); delete r.token_hash; }
  res.json({ codes: rows, total, limit, offset });
});

// Bulk generation. Tokens are stored ENCRYPTED at rest (recoverable only by an
// authorized admin through the panel); nothing is written to any public folder.
router.post('/qr/generate', requirePermission('qr.generate'), (req, res) => {
  if (!isPositiveInt(req.body.batchId)) return res.status(400).json({ error: 'batch_required' });
  const count = intInRange(req.body.count, 1, 100000);
  if (count === null) return res.status(400).json({ error: 'invalid_count' });
  const batch = db.prepare('SELECT * FROM batches WHERE id=?').get(req.body.batchId);
  if (!batch) return res.status(404).json({ error: 'batch_not_found' });

  const tokens = generateQrBatch(batch, count);
  audit({ role: 'admin', id: req.actor.id, action: 'qr_bulk_generate', entity: 'batch', target: batch.id,
    detail: { count: tokens.length }, ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, generated: tokens.length, batchId: batch.id });
});

router.post('/qr/:id/block', requirePermission('qr.block'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  db.prepare(`UPDATE product_qr_codes SET status='blocked' WHERE id=? AND status='unused'`).run(req.params.id);
  audit({ role: 'admin', id: req.actor.id, action: 'qr_block', entity: 'qr', target: Number(req.params.id), severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

/* ---------------- Secure QR print / export (product QR batches) ---------------- */
// Batch list for the print/export workflow (counts + a simple operational status).
router.get('/qr/batches', requirePermission('qr.view'), (req, res) => {
  const rows = db.prepare(
    `SELECT b.id, b.batch_number, b.point_value, b.created_at, s.sku_code, s.size_label, p.name product_name,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id) total,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='used') used,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='unused') unused,
       (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='blocked') blocked
     FROM batches b JOIN skus s ON s.id=b.sku_id JOIN products p ON p.id=s.product_id ORDER BY b.id DESC`
  ).all();
  res.json({ batches: rows });
});

// Re-auth: short-lived confirmation for large/sensitive exports (no secrets in URLs).
router.post('/qr/reauth', (req, res) => {
  const a = db.prepare('SELECT * FROM admins WHERE id=?').get(req.actor.id);
  if (!a || !verifyPassword(String(req.body.password || ''), a.password_hash)) {
    audit({ role: 'admin', id: req.actor.id, action: 'qr_reauth_failed', severity: 'warning', ip: req.ip, requestId: req.requestId });
    return res.status(401).json({ error: 'invalid_password' });
  }
  if (a.mfa_enabled && !verifyTotp(a.totp_secret, String(req.body.totp || ''))) return res.status(401).json({ error: 'mfa_required' });
  req.session.qrReauthAt = Date.now();
  res.json({ ok: true });
});
function reauthOk(req) { return req.session.qrReauthAt && (Date.now() - req.session.qrReauthAt) < 120000; }

// Label PREVIEW (paginated, capped) — decrypts a small range and returns QR data URLs.
router.get('/qr/batches/:id/labels', requirePermission('qr.export'), async (req, res) => {
  const batch = qrx.getBatch.get(req.params.id);
  if (!batch) return res.status(404).json({ error: 'not_found' });
  const total = qrx.countCodes.get(batch.id).c;
  let range;
  try { range = qrx.resolveRange(total, req.query.from, req.query.to, 100); }
  catch (e) { return res.status(400).json({ error: e.code || 'invalid_range' }); }
  const labels = qrx.getLabels(batch, range.from, range.to, baseUrl(req));
  for (const l of labels) l.qr = await qrx.qrDataUrl(req.query.encode === 'token' ? l.token : l.scan_url);
  // strip raw tokens from the preview payload; the QR image already carries them
  const safe = labels.map((l) => ({ seq: l.seq, qr: l.qr, points: l.points, status: l.status, token_ref: (l.token || '').slice(0, 6) + '…' }));
  res.json({ batch: { id: batch.id, batch_number: batch.batch_number, product_name: batch.product_name, sku_code: batch.sku_code }, total, from: range.from, to: range.to, labels: safe });
});

// Streamed exports: CSV / ZIP / PDF. Large ranges require prior /qr/reauth.
router.get('/qr/batches/:id/export/:fmt', requirePermission('qr.export'), async (req, res) => {
  const fmt = req.params.fmt;
  if (!['csv', 'zip', 'pdf'].includes(fmt)) return res.status(400).json({ error: 'invalid_format' });
  const batch = qrx.getBatch.get(req.params.id);
  if (!batch) return res.status(404).json({ error: 'not_found' });
  const total = qrx.countCodes.get(batch.id).c;
  let range;
  try { range = qrx.resolveRange(total, req.query.from, req.query.to || total, config.QR_EXPORT_MAX); }
  catch (e) { return res.status(400).json({ error: e.code || 'invalid_range' }); }

  const size = range.to - range.from + 1;
  if (size > config.QR_EXPORT_REAUTH_THRESHOLD && !reauthOk(req)) {
    return res.status(401).json({ error: 'reauth_required' });
  }

  const useToken = req.query.encode === 'token';
  const labels = qrx.getLabels(batch, range.from, range.to, baseUrl(req));
  const fnameBase = `qr_${String(batch.batch_number).replace(/[^A-Za-z0-9_-]/g, '')}_${range.from}-${range.to}`;
  audit({ role: 'admin', id: req.actor.id, action: `qr_batch_${fmt}_downloaded`, entity: 'batch', target: batch.id,
    detail: { from: range.from, to: range.to, count: size, format: fmt }, severity: 'warning', ip: req.ip, requestId: req.requestId });

  try {
    if (fmt === 'csv') {
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${fnameBase}.csv"`);
      return res.send(qrx.buildCsv(labels));
    }
    if (fmt === 'zip') {
      const buf = await qrx.buildZipOfLabels(labels, useToken);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${fnameBase}.zip"`);
      return res.send(buf);
    }
    // pdf (streamed)
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${fnameBase}.pdf"`);
    return qrx.buildPdf(res, batch, labels, { cols: req.query.cols, orientation: req.query.orientation, useToken });
  } catch (e) {
    if (!res.headersSent) res.status(500).json({ error: 'export_failed', requestId: req.requestId });
  }
});

/* ================================ REWARDS ================================ */
router.get('/rewards', requirePermission('rewards.manage'), (req, res) => {
  res.json({ rewards: db.prepare('SELECT * FROM rewards ORDER BY id DESC').all() });
});

router.post('/rewards', requirePermission('rewards.manage'), (req, res) => {
  const name = cleanText(req.body.name, 80);
  const points = intInRange(req.body.pointsRequired, 1, 10000000);
  const qty = intInRange(req.body.quantity, 0, 10000000);
  if (!name) return res.status(400).json({ error: 'name_required' });
  if (points === null || qty === null) return res.status(400).json({ error: 'invalid_input' });
  const info = db.prepare(`INSERT INTO rewards (name, name_ar, description, description_ar, image, points_required, quantity) VALUES (?,?,?,?,?,?,?)`)
    .run(name, cleanText(req.body.nameAr, 80), cleanText(req.body.description, 300), cleanText(req.body.descriptionAr, 300), cleanText(req.body.image, 300), points, qty);
  audit({ role: 'admin', id: req.actor.id, action: 'reward_create', entity: 'reward', target: info.lastInsertRowid, ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, id: info.lastInsertRowid });
});

router.post('/rewards/:id/status', requirePermission('rewards.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const status = req.body.status === 'inactive' ? 'inactive' : 'active';
  db.prepare('UPDATE rewards SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true, status });
});

/* ================================ WHOLESALERS ================================ */
router.get('/wholesalers', requirePermission('wholesalers.manage'), (req, res) => {
  res.json({ wholesalers: db.prepare(
    `SELECT id, name, location, contact, username, status, created_at,
       (SELECT COUNT(*) FROM redemptions WHERE wholesaler_id=wholesalers.id) redemptions
     FROM wholesalers ORDER BY id DESC`).all() });
});

router.post('/wholesalers', requirePermission('wholesalers.manage'), (req, res) => {
  const name = cleanText(req.body.name, 80);
  const username = cleanText(req.body.username, 40).toLowerCase();
  const password = String(req.body.password || '');
  const email = cleanText(req.body.email, 120).toLowerCase();
  if (!name || !/^[a-z0-9_]{3,40}$/.test(username)) return res.status(400).json({ error: 'invalid_input' });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'invalid_email' });
  if (!isStrongPassword(password)) return res.status(400).json({ error: 'weak_password' });
  const { hashPassword } = require('../crypto');
  try {
    const info = db.prepare(`INSERT INTO wholesalers (name, location, contact, email, username, password_hash) VALUES (?,?,?,?,?,?)`)
      .run(name, cleanText(req.body.location, 80), cleanText(req.body.contact, 40), email || null, username, hashPassword(password));
    audit({ role: 'admin', id: req.actor.id, action: 'wholesaler_create', entity: 'wholesaler', target: info.lastInsertRowid, ip: req.ip, requestId: req.requestId });
    res.json({ ok: true, id: info.lastInsertRowid });
  } catch (e) { if (/UNIQUE/.test(e.message)) return res.status(409).json({ error: 'username_exists' }); throw e; }
});

router.post('/wholesalers/:id/status', requirePermission('wholesalers.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const status = req.body.status === 'inactive' ? 'inactive' : 'active';
  db.prepare('UPDATE wholesalers SET status=? WHERE id=?').run(status, req.params.id);
  res.json({ ok: true, status });
});

/* ================================ FRAUD REVIEWS ================================ */
router.get('/reviews', requirePermission('reviews.manage'), (req, res) => {
  const rows = db.prepare(
    `SELECT rv.*, f.name farmer_name, f.mobile FROM risk_reviews rv JOIN farmers f ON f.id=rv.farmer_id
     ORDER BY (rv.status='open') DESC, rv.id DESC LIMIT 200`).all();
  res.json({ reviews: rows });
});
router.post('/reviews/:id/approve', requirePermission('reviews.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const r = approveReview(req.actor.id, Number(req.params.id), { ip: req.ip, requestId: req.requestId });
  if (!r.ok) return res.status(409).json({ error: r.code }); res.json({ ok: true });
});
router.post('/reviews/:id/reject', requirePermission('reviews.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const r = rejectReview(req.actor.id, Number(req.params.id), { ip: req.ip, requestId: req.requestId });
  if (!r.ok) return res.status(409).json({ error: r.code }); res.json({ ok: true });
});
router.post('/redemptions/:id/cancel', requirePermission('redemptions.cancel'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const r = cancelRedemption(req.actor.id, Number(req.params.id), cleanText(req.body.reason, 120), { ip: req.ip, requestId: req.requestId });
  if (!r.ok) return res.status(409).json({ error: r.code }); res.json({ ok: true, balance: r.balance });
});

/* ================================ REPORTS / ANALYTICS ================================ */
router.get('/reports', requirePermission('reports.view'), (req, res) => {
  const registrationsByDate = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM farmers GROUP BY d ORDER BY d DESC LIMIT 30`).all();
  const scansByDate = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM points_transactions WHERE type='earn' GROUP BY d ORDER BY d DESC LIMIT 30`).all();
  const mostScannedProducts = db.prepare(`SELECT p.name, COUNT(*) scans, COALESCE(SUM(t.points),0) points FROM points_transactions t JOIN product_qr_codes q ON q.id=t.qr_id JOIN products p ON p.id=q.product_id WHERE t.type='earn' GROUP BY p.id ORDER BY scans DESC`).all();
  const popularRewards = db.prepare(`SELECT rw.name, COUNT(*) redemptions, SUM(r.points_spent) points FROM redemptions r JOIN rewards rw ON rw.id=r.reward_id GROUP BY rw.id ORDER BY redemptions DESC`).all();
  const redemptionsPerWholesaler = db.prepare(`SELECT w.name, COUNT(r.id) redemptions FROM wholesalers w LEFT JOIN redemptions r ON r.wholesaler_id=w.id GROUP BY w.id ORDER BY redemptions DESC`).all();
  const batchPerformance = db.prepare(`SELECT b.batch_number, p.name product, b.qr_count generated, (SELECT COUNT(*) FROM product_qr_codes WHERE batch_id=b.id AND status='used') used FROM batches b JOIN skus s ON s.id=b.sku_id JOIN products p ON p.id=s.product_id ORDER BY b.id DESC`).all();
  const qrUsage = {
    unused: db.prepare(`SELECT COUNT(*) c FROM product_qr_codes WHERE status='unused'`).get().c,
    used: db.prepare(`SELECT COUNT(*) c FROM product_qr_codes WHERE status='used'`).get().c,
    blocked: db.prepare(`SELECT COUNT(*) c FROM product_qr_codes WHERE status='blocked'`).get().c,
  };
  const suspicious = db.prepare(`SELECT action, severity, detail, created_at FROM audit_logs WHERE severity IN ('warning','alert') ORDER BY id DESC LIMIT 50`).all();
  res.json({ registrationsByDate, scansByDate, mostScannedProducts, popularRewards, redemptionsPerWholesaler, batchPerformance, qrUsage, suspicious });
});

router.get('/reports/export', requirePermission('reports.view'), (req, res) => {
  const map = {
    farmers: `SELECT id, name, mobile, points_balance, status, created_at FROM farmers ORDER BY id`,
    scans: `SELECT date(created_at) date, COUNT(*) scans FROM points_transactions WHERE type='earn' GROUP BY date ORDER BY date`,
    redemptions: `SELECT r.code, f.name farmer, rw.name reward, r.points_spent, r.status, r.created_at FROM redemptions r JOIN farmers f ON f.id=r.farmer_id JOIN rewards rw ON rw.id=r.reward_id ORDER BY r.id`,
    products: `SELECT p.name, COUNT(*) scans FROM points_transactions t JOIN product_qr_codes q ON q.id=t.qr_id JOIN products p ON p.id=q.product_id WHERE t.type='earn' GROUP BY p.id ORDER BY scans DESC`,
  };
  if (!map[req.query.type]) return res.status(400).json({ error: 'invalid_type' });
  sendCSV(res, `report_${req.query.type}.csv`, db.prepare(map[req.query.type]).all());
});

router.get('/audit', requirePermission('audit.view'), (req, res) => {
  const { limit, offset } = paging(req);
  const total = db.prepare('SELECT COUNT(*) c FROM audit_logs').get().c;
  const logs = db.prepare(`SELECT id, request_id, actor_role, actor_id, action, entity, target_id, detail, severity, ip, created_at FROM audit_logs ORDER BY id DESC LIMIT @limit OFFSET @offset`).all({ limit, offset });
  res.json({ logs, total, limit, offset });
});

/* ================================ REDEMPTIONS ================================ */
router.get('/redemptions', requirePermission('redemptions.view'), (req, res) => {
  const { limit, offset } = paging(req);
  const status = ['pending', 'redeemed', 'expired', 'cancelled'].includes(req.query.status) ? req.query.status : null;
  const q = cleanText(req.query.q, 40);
  const clauses = []; const params = { limit, offset };
  if (status) { clauses.push('r.status=@status'); params.status = status; }
  if (q) { clauses.push('(r.code LIKE @like OR f.name LIKE @like OR f.mobile LIKE @like)'); params.like = `%${q}%`; }
  const where = clauses.length ? 'WHERE ' + clauses.join(' AND ') : '';
  const total = db.prepare(`SELECT COUNT(*) c FROM redemptions r JOIN farmers f ON f.id=r.farmer_id ${where}`).get(params).c;
  const rows = db.prepare(
    `SELECT r.id, r.code, r.status, r.points_spent, r.created_at, r.completed_at, r.expires_at,
            f.name farmer_name, f.mobile farmer_mobile, rw.name reward_name, w.name wholesaler_name
     FROM redemptions r JOIN farmers f ON f.id=r.farmer_id JOIN rewards rw ON rw.id=r.reward_id
     LEFT JOIN wholesalers w ON w.id=r.wholesaler_id ${where}
     ORDER BY r.id DESC LIMIT @limit OFFSET @offset`
  ).all(params);
  res.json({ redemptions: rows, total, limit, offset });
});

/* ================================ SETTINGS (fraud thresholds etc.) ================================ */
router.get('/settings', requirePermission('settings.manage'), (req, res) => res.json({ settings: settings.all() }));
router.put('/settings', requirePermission('settings.manage'), (req, res) => {
  const { key, value } = req.body || {};
  if (typeof key !== 'string' || !(key in settings.DEFAULTS)) return res.status(400).json({ error: 'invalid_key' });
  settings.set(key, value);
  audit({ role: 'admin', id: req.actor.id, action: 'settings_update', entity: 'settings', detail: { key }, severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

/* ================================ ADMIN MFA (self-service) ================================ */
router.post('/mfa/setup', (req, res) => {
  const secret = generateTotpSecret();
  req.session.pendingTotp = secret;
  const admin = db.prepare('SELECT username FROM admins WHERE id=?').get(req.actor.id);
  res.json({ secret, otpauth: totpUri(secret, admin.username) });
});
router.post('/mfa/enable', (req, res) => {
  const secret = req.session.pendingTotp;
  if (!secret) return res.status(400).json({ error: 'no_pending_setup' });
  if (!verifyTotp(secret, String(req.body.code || ''))) return res.status(401).json({ error: 'invalid_code' });
  db.prepare('UPDATE admins SET mfa_enabled=1, totp_secret=? WHERE id=?').run(secret, req.actor.id);
  delete req.session.pendingTotp;
  audit({ role: 'admin', id: req.actor.id, action: 'mfa_enabled', severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});
router.post('/mfa/disable', (req, res) => {
  db.prepare('UPDATE admins SET mfa_enabled=0, totp_secret=NULL WHERE id=?').run(req.actor.id);
  audit({ role: 'admin', id: req.actor.id, action: 'mfa_disabled', severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

/* ================================ STAFF USER MANAGEMENT ================================ */
// SUPER_ADMIN only (users.manage). Protects the last active SUPER_ADMIN from
// being disabled, archived, or demoted so the system can never be locked out.
const activeSuperAdmins = () => db.prepare(`SELECT COUNT(*) c FROM admins WHERE role='SUPER_ADMIN' AND status='active'`).get().c;
const isLastActiveSuper = (admin) => admin && admin.role === 'SUPER_ADMIN' && admin.status === 'active' && activeSuperAdmins() <= 1;

router.get('/users', requirePermission('users.manage'), (req, res) => {
  const rows = db.prepare(
    `SELECT id, username, name, role, status, mfa_enabled, must_change_password, last_login_at, created_at
     FROM admins ORDER BY id`
  ).all();
  for (const r of rows) r.active_sessions = sessions.activeCount('admin', r.id);
  res.json({ users: rows, roles: STAFF_ROLES });
});

router.post('/users', requirePermission('users.manage'), (req, res) => {
  const username = cleanText(req.body.username, 40).toLowerCase();
  const name = cleanText(req.body.name, 80);
  const email = cleanText(req.body.email, 120).toLowerCase();
  const role = req.body.role;
  if (!/^[a-z0-9_.]{3,40}$/.test(username) || !name) return res.status(400).json({ error: 'invalid_input' });
  if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'invalid_email' });
  if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'invalid_role' });
  const temp = tempPassword();
  try {
    const info = db.prepare(
      `INSERT INTO admins (username, name, email, password_hash, role, must_change_password) VALUES (?,?,?,?,?,1)`
    ).run(username, name, email || null, hashPassword(temp), role);
    audit({ role: 'admin', id: req.actor.id, action: 'user_created', entity: 'admin', target: info.lastInsertRowid,
      detail: { username, role }, severity: 'warning', ip: req.ip, requestId: req.requestId });
    // Temp password returned ONCE to the creating admin; never stored in plaintext.
    res.json({ ok: true, id: info.lastInsertRowid, username, tempPassword: temp });
  } catch (e) { if (/UNIQUE/.test(e.message)) return res.status(409).json({ error: 'username_exists' }); throw e; }
});

router.post('/users/:id/role', requirePermission('users.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const role = req.body.role;
  if (!STAFF_ROLES.includes(role)) return res.status(400).json({ error: 'invalid_role' });
  const target = db.prepare('SELECT * FROM admins WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not_found' });
  if (role !== 'SUPER_ADMIN' && isLastActiveSuper(target)) return res.status(409).json({ error: 'last_super_admin' });
  db.prepare('UPDATE admins SET role=? WHERE id=?').run(role, target.id);
  audit({ role: 'admin', id: req.actor.id, action: 'user_role_changed', entity: 'admin', target: target.id,
    detail: { from: target.role, to: role }, severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, role });
});

router.post('/users/:id/status', requirePermission('users.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const status = ['active', 'disabled', 'archived'].includes(req.body.status) ? req.body.status : null;
  if (!status) return res.status(400).json({ error: 'invalid_status' });
  const target = db.prepare('SELECT * FROM admins WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not_found' });
  if (status !== 'active' && isLastActiveSuper(target)) return res.status(409).json({ error: 'last_super_admin' });
  db.prepare('UPDATE admins SET status=? WHERE id=?').run(status, target.id);
  if (status !== 'active') sessions.revokeAll('admin', target.id); // disabled/archived => kill sessions
  audit({ role: 'admin', id: req.actor.id, action: 'user_status_change', entity: 'admin', target: target.id,
    detail: { status }, severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, status });
});

// Reset a user's authentication: new temporary password + forced change + all sessions revoked.
router.post('/users/:id/reset-password', requirePermission('users.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const target = db.prepare('SELECT * FROM admins WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ error: 'not_found' });
  const temp = tempPassword();
  db.prepare('UPDATE admins SET password_hash=?, must_change_password=1, failed_attempts=0, locked_until=NULL WHERE id=?')
    .run(hashPassword(temp), target.id);
  sessions.revokeAll('admin', target.id);
  audit({ role: 'admin', id: req.actor.id, action: 'user_password_reset', entity: 'admin', target: target.id,
    severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, tempPassword: temp });
});

router.post('/users/:id/revoke-sessions', requirePermission('users.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  sessions.revokeAll('admin', Number(req.params.id));
  audit({ role: 'admin', id: req.actor.id, action: 'user_sessions_revoked', entity: 'admin', target: Number(req.params.id),
    severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

/* ---- Wholesaler credential ops (managed alongside the Wholesalers section) ---- */
router.post('/wholesalers/:id/reset-password', requirePermission('wholesalers.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  const w = db.prepare('SELECT id FROM wholesalers WHERE id=?').get(req.params.id);
  if (!w) return res.status(404).json({ error: 'not_found' });
  const temp = tempPassword();
  db.prepare('UPDATE wholesalers SET password_hash=?, must_change_password=1, failed_attempts=0, locked_until=NULL WHERE id=?')
    .run(hashPassword(temp), w.id);
  sessions.revokeAll('wholesaler', w.id);
  audit({ role: 'admin', id: req.actor.id, action: 'wholesaler_password_reset', entity: 'wholesaler', target: w.id,
    severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true, tempPassword: temp });
});
router.post('/wholesalers/:id/revoke-sessions', requirePermission('wholesalers.manage'), (req, res) => {
  if (!isPositiveInt(req.params.id)) return res.status(400).json({ error: 'invalid' });
  sessions.revokeAll('wholesaler', Number(req.params.id));
  audit({ role: 'admin', id: req.actor.id, action: 'wholesaler_sessions_revoked', entity: 'wholesaler', target: Number(req.params.id),
    severity: 'warning', ip: req.ip, requestId: req.requestId });
  res.json({ ok: true });
});

module.exports = router;
