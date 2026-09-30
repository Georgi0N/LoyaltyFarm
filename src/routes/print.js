'use strict';
/**
 * Secure QR PRINT page (HTML, browsable). Mounted at /admin/print.
 *
 *   GET /admin/print/qr/:batchId?from=1&to=50&cols=3
 *
 * Unlike the JSON API this returns HTML and handles auth for a browser:
 *   - not logged in            -> redirect to the admin login
 *   - logged in but not admin  -> 403 page (farmer / wholesaler denied)
 *   - admin without qr.export  -> 403 page
 * The URL carries only the internal batch id + a print range — never a token.
 */
const express = require('express');
const { db, audit } = require('../db');
const config = require('../config');
const { hasPermission } = require('../rbac');
const qrx = require('../qrexport');

const router = express.Router();
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const deny = (res, code, msg) => res.status(code).send(
  `<!doctype html><meta charset="utf-8"><title>${code}</title>
   <div style="font-family:system-ui;max-width:520px;margin:16vh auto;text-align:center;color:#10241b">
   <h1 style="font-size:2rem">${code}</h1><p style="color:#6b7d75">${esc(msg)}</p>
   <a href="/admin" style="color:#0e7a43">Go to admin</a></div>`);

function guard(req, res, next) {
  const u = req.session && req.session.user;
  if (!u) return res.redirect('/admin');                 // logged out -> login
  if (u.role !== 'admin') return deny(res, 403, 'Access denied.'); // farmer/wholesaler
  const row = db.prepare('SELECT revoked FROM sessions WHERE sid=?').get(req.sessionID);
  if (row && row.revoked) return res.redirect('/admin');
  const a = db.prepare('SELECT status, role FROM admins WHERE id=?').get(u.id);
  if (!a || a.status !== 'active') return res.redirect('/admin');
  if (!hasPermission(a.role, 'qr.export')) return deny(res, 403, 'You do not have permission to print QR codes.');
  req._adminRole = a.role;
  next();
}

router.get('/qr/:batchId', guard, async (req, res) => {
  const batch = qrx.getBatch.get(req.params.batchId);
  if (!batch) return deny(res, 404, 'Batch not found.');
  const total = qrx.countCodes.get(batch.id).c;
  let range;
  try { range = qrx.resolveRange(total, req.query.from, req.query.to || Math.min(total, 50), 500); }
  catch (e) { return deny(res, 400, 'Invalid print range.'); }

  const cols = Math.min(4, Math.max(2, parseInt(req.query.cols, 10) || 3));
  const base = config.APP_URL || `${req.protocol}://${req.get('host')}`;
  const labels = qrx.getLabels(batch, range.from, range.to, base);
  const imgs = [];
  for (const l of labels) imgs.push({ ...l, qr: await qrx.qrDataUrl(req.query.encode === 'token' ? l.token : l.scan_url) });

  audit({ role: 'admin', id: req.session.user.id, action: 'qr_batch_print_view', entity: 'batch', target: batch.id,
    detail: { from: range.from, to: range.to, count: imgs.length }, ip: req.ip, requestId: req.requestId });

  res.send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Print — ${esc(batch.batch_number)}</title>
<style>
  :root { --ink:#10241b; --muted:#6b7d75; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, Arial, sans-serif; margin: 0; color: var(--ink); background: #f5f8f6; }
  .bar { position: sticky; top: 0; background: #fff; border-bottom: 1px solid #e6ece8; padding: 12px 16px; display: flex; gap: 12px; align-items: center; }
  .bar b { font-size: 15px; } .bar .muted { color: var(--muted); font-size: 13px; }
  .bar button { margin-left: auto; padding: 9px 16px; border: 0; border-radius: 8px; background: #22a65c; color: #fff; font-weight: 700; cursor: pointer; }
  .sheet { max-width: 1000px; margin: 16px auto; background: #fff; padding: 12mm; border-radius: 8px; }
  .grid { display: grid; grid-template-columns: repeat(${cols}, 1fr); gap: 8mm; }
  .label { border: 1px dashed #cfe0d6; border-radius: 8px; padding: 8px; text-align: center; page-break-inside: avoid; }
  .label img { width: 100%; height: auto; image-rendering: pixelated; }
  .label .tok { font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; letter-spacing: .03em; margin-top: 3px; word-break: break-all; }
  .label .meta { font-size: 10px; color: var(--muted); }
  .label .cta { font-size: 10px; color: #0e7a43; font-weight: 700; }
  @media print {
    .bar { display: none !important; }
    body, .sheet { background: #fff; margin: 0; padding: 0; border-radius: 0; }
    .sheet { max-width: none; padding: 8mm; }
    @page { size: A4 ${req.query.orientation === 'landscape' ? 'landscape' : 'portrait'}; margin: 8mm; }
  }
</style></head>
<body>
  <div class="bar">
    <b>${esc(batch.product_name)} · ${esc(batch.sku_code)}</b>
    <span class="muted">${esc(batch.batch_number)} · labels ${range.from}–${range.to} of ${total}</span>
    <button onclick="window.print()">Print</button>
  </div>
  <div class="sheet"><div class="grid">
    ${imgs.map((l) => `<div class="label">
      <img src="${l.qr}" alt="QR ${l.seq}">
      <div class="tok">${esc(l.token || '')}</div>
      <div class="meta">${esc(batch.product_name)} · ${esc(l.points)} pts</div>
      <div class="cta">Scan to earn points</div>
    </div>`).join('')}
  </div></div>
</body></html>`);
});

module.exports = router;
