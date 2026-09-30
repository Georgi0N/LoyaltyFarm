'use strict';
/**
 * Seed realistic demo data for the hardened schema.
 *   npm run seed    (adds data if empty)
 *   npm run reset   (drops + rebuilds + reseeds)
 *
 * Because only token HASHES are stored, a set of valid plaintext demo tokens is
 * written to data/demo-tokens.txt (gitignored, DEV ONLY) so the prototype can be
 * exercised end-to-end. This file must never exist in production.
 */
const fs = require('fs');
const path = require('path');
const config = require('./config');
const { db, audit, rebuild } = require('./db');
const { hashPassword, redemptionToken, redemptionCode, hashRedemptionToken } = require('./crypto');
const { generateQrBatch } = require('./services');

// Never auto-seed a production database (demo accounts + demo tokens are dev-only).
if (config.IS_PROD && !process.argv.includes('--force')) {
  console.error('Refusing to seed in production (APP_ENV=production). Use --force only if you are certain.');
  process.exit(1);
}

const RESET = process.argv.includes('--reset');
if (RESET) { rebuild(); console.log('Rebuilt schema (clean).'); }

if (db.prepare('SELECT COUNT(*) c FROM admins').get().c && !RESET) {
  console.log('Data already present. Use `npm run reset` to rebuild.');
  process.exit(0);
}

const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = (arr) => arr[rnd(0, arr.length - 1)];
const daysAgo = (n) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 19).replace('T', ' ');

/* ------------------------------- Admins (roles) ------------------------------- */
db.prepare('INSERT INTO admins (username, name, email, password_hash, role) VALUES (?,?,?,?,?)')
  .run('admin', 'Program Administrator', 'admin@hasad.local', hashPassword('admin123'), 'SUPER_ADMIN');
db.prepare('INSERT INTO admins (username, name, email, password_hash, role) VALUES (?,?,?,?,?)')
  .run('manager', 'Program Manager', 'manager@hasad.local', hashPassword('Manager@123'), 'PROGRAM_MANAGER');
db.prepare('INSERT INTO admins (username, name, email, password_hash, role) VALUES (?,?,?,?,?)')
  .run('viewer', 'Report Viewer', 'viewer@hasad.local', hashPassword('Viewer@123'), 'REPORT_VIEWER');

/* ------------------------------- Wholesalers ------------------------------- */
const wholesalers = [
  ['Baghdad Agri Center', 'Baghdad - Karrada', '+964 770 123 4567', 'baghdad'],
  ['Basra Farm Supplies', 'Basra - Ashar', '+964 771 234 5678', 'basra'],
  ['Mosul Green Depot', 'Mosul - Al-Majmoua', '+964 772 345 6789', 'mosul'],
];
const wIds = wholesalers.map(([name, location, contact, username]) =>
  db.prepare('INSERT INTO wholesalers (name, location, contact, email, username, password_hash) VALUES (?,?,?,?,?,?)')
    .run(name, location, contact, `${username}@hasad.local`, username, hashPassword('Wholesale@123')).lastInsertRowid);

/* ------------------------------- Products + SKUs ------------------------------- */
const productDefs = [
  { name: 'Fertilizer X', category: 'Fertilizers', skus: [['FRTX-25', '25 KG', 100], ['FRTX-50', '50 KG', 200]] },
  { name: 'UreaGrow', category: 'Fertilizers', skus: [['UREA-50', '50 KG', 180]] },
  { name: 'CropShield Pesticide', category: 'Pesticides', skus: [['CSHP-1L', '1 Litre', 60], ['CSHP-5L', '5 Litre', 250]] },
  { name: 'Premium Wheat Seeds', category: 'Seeds', skus: [['PWS-10', '10 KG', 80]] },
  { name: 'HydroBoost Nutrient', category: 'Nutrients', skus: [['HYB-2L', '2 Litre', 120]] },
];
const skuRows = [];
for (const p of productDefs) {
  const pid = db.prepare('INSERT INTO products (name, category) VALUES (?,?)').run(p.name, p.category).lastInsertRowid;
  for (const [code, size, pts] of p.skus) {
    const sid = db.prepare('INSERT INTO skus (product_id, sku_code, size_label, default_points) VALUES (?,?,?,?)').run(pid, code, size, pts).lastInsertRowid;
    skuRows.push({ id: sid, product_id: pid, points: pts });
  }
}

/* ------------------------------- Batches + QR codes ------------------------------- */
const months = ['JUL', 'AUG', 'SEP'];
const batchRows = [];
skuRows.forEach((s, i) => {
  const bn = `IRQ-${pick(months)}-2026-${String(i + 1).padStart(2, '0')}`;
  const bid = db.prepare(`INSERT INTO batches (sku_id, batch_number, production_date, expiry_date, point_value) VALUES (?,?,?,?,?)`)
    .run(s.id, bn, daysAgo(rnd(30, 90)).slice(0, 10), daysAgo(-540).slice(0, 10), s.points).lastInsertRowid;
  const batch = db.prepare('SELECT * FROM batches WHERE id=?').get(bid);
  generateQrBatch(batch, rnd(120, 200));
  batchRows.push({ id: bid, points: s.points });
});
console.log(`Generated ${db.prepare('SELECT COUNT(*) c FROM product_qr_codes').get().c} secure QR codes (hash-only).`);

/* ------------------------------- Rewards ------------------------------- */
const rewards = [
  ['Agricultural Sprayer', 'رشاشة زراعية', '16L backpack sprayer for crop protection.', 'رشاشة ظهرية سعة 16 لتر لحماية المحاصيل.', 'sprayer', 1200, 40],
  ['Premium Seed Pack', 'حزمة بذور ممتازة', 'High-yield certified seed bundle.', 'حزمة بذور معتمدة عالية الإنتاجية.', 'seeds', 600, 100],
  ['Hand Tools Kit', 'طقم أدوات يدوية', 'Durable set of essential farming hand tools.', 'مجموعة متينة من أدوات الزراعة الأساسية.', 'tools', 400, 150],
  ['Irrigation Hose 50m', 'خرطوم ري 50 متر', 'Heavy-duty 50 meter irrigation hose.', 'خرطوم ري متين بطول 50 متر.', 'hose', 900, 60],
  ['Fertilizer Voucher', 'قسيمة سماد', 'Discount voucher toward your next fertilizer purchase.', 'قسيمة خصم على شرائك القادم من السماد.', 'voucher', 300, 300],
  ['Solar Water Pump', 'مضخة مياه شمسية', 'Eco-friendly solar-powered water pump.', 'مضخة مياه تعمل بالطاقة الشمسية صديقة للبيئة.', 'pump', 5000, 10],
];
const rewardIds = rewards.map((r) =>
  db.prepare(`INSERT INTO rewards (name, name_ar, description, description_ar, image, points_required, quantity) VALUES (?,?,?,?,?,?,?)`).run(...r).lastInsertRowid);

/* ------------------------------- Farmers + simulated activity ------------------------------- */
const firstNames = ['Ahmad', 'Ali', 'Hassan', 'Mohammed', 'Omar', 'Yusuf', 'Karim', 'Sabah', 'Fadhil', 'Jasim', 'Salim', 'Hamid'];
const lastNames = ['Hassan', 'Al-Obaidi', 'Kadhim', 'Al-Jubouri', 'Aziz', 'Al-Dulaimi', 'Rashid', 'Al-Maliki'];

const unusedByBatch = db.prepare(`SELECT id, point_value FROM product_qr_codes WHERE batch_id=? AND status='unused' LIMIT ?`);
const useQr = db.prepare(`UPDATE product_qr_codes SET status='used', claimed_by=?, claimed_at=? WHERE id=?`);
const addLedger = db.prepare(`INSERT INTO points_transactions (farmer_id, type, source, points, prev_balance, balance_after, qr_id, redemption_id, description, created_by_role, created_by_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`);
const setBalance = db.prepare('UPDATE farmers SET points_balance=? WHERE id=?');

const farmerIds = [];
for (let i = 0; i < 45; i++) {
  const name = `${pick(firstNames)} ${pick(lastNames)}`;
  const mobile = '+9647' + rnd(0, 9) + String(rnd(0, 99999999)).padStart(8, '0'); // E.164 (Iraq demo data)
  const regDays = rnd(1, 40);
  const lang = Math.random() < 0.6 ? 'ar' : 'en';
  let fid;
  try { fid = db.prepare('INSERT INTO farmers (mobile, name, language, created_at) VALUES (?,?,?,?)').run(mobile, name, lang, daysAgo(regDays)).lastInsertRowid; }
  catch { continue; }
  farmerIds.push(fid);

  let balance = 0;
  for (let s = 0, n = rnd(0, 14); s < n; s++) {
    const batch = pick(batchRows);
    const codes = unusedByBatch.all(batch.id, 1);
    if (!codes.length) continue;
    const c = codes[0]; const when = daysAgo(rnd(0, regDays));
    useQr.run(fid, when, c.id);
    const prev = balance; balance += c.point_value;
    addLedger.run(fid, 'earn', 'PRODUCT_PURCHASE', c.point_value, prev, balance, c.id, null, 'Product scan', 'farmer', fid, when);
  }
  setBalance.run(balance, fid);
}
console.log(`Created ${farmerIds.length} farmers with scan history.`);

/* ------------------------------- Redemptions ------------------------------- */
const insertRedemption = db.prepare(
  `INSERT INTO redemptions (code, token, token_hash, farmer_id, reward_id, points_spent, status, wholesaler_id, expires_at, created_at, completed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`);
let redemptionCount = 0;
for (const fid of farmerIds) {
  const f = db.prepare('SELECT * FROM farmers WHERE id=?').get(fid);
  const affordable = rewards.map((r, idx) => ({ id: rewardIds[idx], points: r[5], name: r[0] })).filter((r) => r.points <= f.points_balance);
  if (!affordable.length || Math.random() > 0.5) continue;
  const reward = pick(affordable);
  const completed = Math.random() < 0.6;
  const when = daysAgo(rnd(0, 15));
  const wid = completed ? pick(wIds) : null;
  const tok = redemptionToken();
  const expires = daysAgo(-30);
  const rid = insertRedemption.run(redemptionCode(), tok, hashRedemptionToken(tok), fid, reward.id, reward.points,
    completed ? 'redeemed' : 'pending', wid, expires, when, completed ? when : null).lastInsertRowid;
  const prev = f.points_balance; const after = prev - reward.points;
  setBalance.run(after, fid);
  addLedger.run(fid, 'redeem', 'REWARD_REDEMPTION', -reward.points, prev, after, null, rid, `Redeemed: ${reward.name}`, 'farmer', fid, when);
  db.prepare('UPDATE rewards SET quantity = quantity - 1 WHERE id=?').run(reward.id);
  redemptionCount++;
}
console.log(`Created ${redemptionCount} redemptions.`);

/* ------------------------------- Suspicious samples ------------------------------- */
for (let i = 0; i < 8; i++) {
  audit({ role: 'farmer', id: pick(farmerIds), action: pick(['suspicious_scan', 'duplicate_scan']),
    entity: 'qr', detail: { reason: pick(['invalid_token', 'already_used']) }, severity: pick(['warning', 'alert']), ip: `10.0.${rnd(0, 255)}.${rnd(0, 255)}` });
}

/* ------------------------------- DEV demo tokens (never in prod) ------------------------------- */
const demoBatchSku = skuRows[0];
const demoBid = db.prepare(`INSERT INTO batches (sku_id, batch_number, production_date, expiry_date, point_value) VALUES (?,?,?,?,?)`)
  .run(demoBatchSku.id, 'IRQ-DEMO-2026-99', daysAgo(5).slice(0, 10), daysAgo(-540).slice(0, 10), 100).lastInsertRowid;
const demoTokens = generateQrBatch(db.prepare('SELECT * FROM batches WHERE id=?').get(demoBid), 60);
fs.writeFileSync(path.join(__dirname, '..', 'data', 'demo-tokens.txt'),
  '# DEV ONLY — valid unused product QR tokens for manual testing. Do NOT ship to production.\n' + demoTokens.join('\n') + '\n');
console.log(`Wrote ${demoTokens.length} demo tokens to data/demo-tokens.txt (dev only).`);

console.log('\nSeed complete.');
console.log('  Admin:       admin / admin123   (also manager / Manager@123 · viewer / Viewer@123)');
console.log('  Wholesaler:  baghdad / Wholesale@123   (also basra, mosul)');
console.log('  Farmer:      OTP login — dev OTP is printed to this server console.\n');
process.exit(0);
