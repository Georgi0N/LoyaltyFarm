'use strict';
/**
 * Full end-to-end journey with freshly AUTHORED data (not demo tokens):
 *   ADMIN  create product -> SKU -> batch -> generate QR (print file)
 *   FARMER OTP register -> scan generated tokens -> redeem reward
 *   WHOLESALER lookup -> confirm handover
 *   ADMIN  verify redemption + farmer balance + audit
 *
 *   node server.js  (terminal 1)   |   node scripts/journey.js  (terminal 2)
 */
const fs = require('fs');
const path = require('path');
const BASE = 'http://localhost:3000';

function client() {
  let cookie = '', csrf = '';
  async function req(p, { method = 'GET', body, headers = {} } = {}) {
    const h = { ...headers };
    if (cookie) h.Cookie = cookie;
    if (method !== 'GET') { h['X-CSRF-Token'] = csrf; if (body !== undefined) h['Content-Type'] = 'application/json'; }
    const res = await fetch(BASE + p, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
    const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (sc.length) cookie = sc.map((c) => c.split(';')[0]).join('; ');
    let data = null; try { data = await res.json(); } catch {}
    return { status: res.status, data };
  }
  async function text(p) {
    const h = {}; if (cookie) h.Cookie = cookie;
    const res = await fetch(BASE + p, { headers: h });
    return { status: res.status, body: await res.text() };
  }
  return { raw: req, text, async csrf() { csrf = (await req('/api/csrf')).data.csrfToken; }, get: (p) => req(p), post: (p, b) => req(p, { method: 'POST', body: b }) };
}

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };

(async () => {
  const rid = Math.floor(Math.random() * 1e6);

  console.log('\nADMIN AUTHORS A CAMPAIGN');
  const a = client(); await a.csrf();
  ok((await a.post('/api/auth/admin', { username: 'admin', password: 'admin123' })).status === 200, 'admin logs in');
  const prod = await a.post('/api/admin/products', { name: 'Journey Fertilizer ' + rid, category: 'Fertilizers' });
  ok(prod.status === 200, 'create product');
  const sku = await a.post('/api/admin/skus', { productId: prod.data.id, skuCode: 'JRN-' + rid, sizeLabel: '25 KG', defaultPoints: 500 });
  ok(sku.status === 200, 'create SKU');
  const batch = await a.post('/api/admin/batches', { skuId: sku.data.id, batchNumber: 'IRQ-JRN-' + rid, pointValue: 500 });
  ok(batch.status === 200, 'create batch');
  const gen = await a.post('/api/admin/qr/generate', { batchId: batch.data.id, count: 5 });
  ok(gen.status === 200 && gen.data.generated === 5 && gen.data.exportFile, 'generate 5 secure QR codes + print file');

  // Read the freshly generated tokens from the print file (as a label printer would).
  const csv = fs.readFileSync(path.join(__dirname, '..', 'data', 'exports', gen.data.exportFile), 'utf8').trim().split('\n');
  const header = csv[0].replace(/^﻿/, '').split(',').map((s) => s.replace(/"/g, ''));
  const tokCol = header.indexOf('token');
  const tokens = csv.slice(1).map((line) => line.split(',')[tokCol].replace(/"/g, ''));
  ok(tokens.length === 5 && tokens.every((t) => /^[A-Z0-9]{20,}$/.test(t)), 'print file contains 5 usable high-entropy tokens');

  console.log('\nFARMER EARNS & REDEEMS');
  const f = client(); await f.csrf();
  const mobile = '07' + '7' + String(rid).padStart(8, '0').slice(0, 8);
  const otp = await f.post('/api/auth/farmer/request-otp', { mobile });
  await f.post('/api/auth/farmer/verify-otp', { mobile, code: otp.data.devCode });
  ok((await f.post('/api/auth/farmer/register', { name: 'Journey Farmer', language: 'en' })).status === 200, 'farmer registers via OTP');

  let bal = 0;
  for (const t of tokens.slice(0, 3)) { const s = await f.post('/api/farmer/scan', { token: t }); if (s.data.balance) bal = s.data.balance; }
  ok(bal === 1500, `scanning 3 authored codes credits 1500 points (got ${bal})`);

  const rewards = (await f.get('/api/farmer/rewards')).data.rewards;
  const reward = rewards.filter((r) => r.quantity > 0 && r.points_required <= bal).sort((x, y) => x.points_required - y.points_required)[0];
  const red = await f.post('/api/farmer/redeem', { rewardId: reward.id });
  ok(red.status === 200 && red.data.code, `redeem "${reward.name}" -> code ${red.data.code}`);
  const redemptionCode = red.data.code, redemptionToken = red.data.token;

  console.log('\nWHOLESALER CONFIRMS HANDOVER');
  const w = client(); await w.csrf();
  await w.post('/api/auth/wholesaler', { username: 'basra', password: 'Wholesale@123' });
  const look = await w.post('/api/wholesaler/lookup', { code: redemptionToken });
  ok(look.status === 200 && !look.data.redemption.already_completed, 'wholesaler validates redemption');
  ok(/^\d{3}\*+\d{2}$/.test(look.data.redemption.farmer_mobile), 'farmer phone is masked to the wholesaler');
  ok((await w.post('/api/wholesaler/confirm', { redemptionId: look.data.redemption.id })).status === 200, 'confirm gift handover');
  ok((await w.post('/api/wholesaler/lookup', { code: redemptionCode })).data.redemption.already_completed, 'code is now single-use spent');

  console.log('\nADMIN VERIFIES');
  const red2 = (await a.get('/api/admin/redemptions?q=' + redemptionCode)).data.redemptions[0];
  ok(red2 && red2.status === 'redeemed' && red2.wholesaler_name, 'admin sees redemption as redeemed with wholesaler');
  const audit = (await a.get('/api/admin/audit?limit=50')).data.logs.map((l) => l.action);
  ok(audit.includes('qr_bulk_generate') && audit.includes('redemption_completed'), 'audit trail recorded generation + completion');

  console.log(`\n==== JOURNEY: ${pass} passed, ${fail} failed ====`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
