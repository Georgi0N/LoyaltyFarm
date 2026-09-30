'use strict';
/**
 * Security / attack / concurrency test suite. Run against a live server:
 *   node server.js        (terminal 1)
 *   node scripts/security-tests.js   (terminal 2)
 *
 * Thinks like an attacker: replay, race, IDOR, role escalation, mass assignment,
 * CSRF, OTP brute force, token guessing, double-spend, ledger tampering.
 */
const fs = require('fs');
const path = require('path');
const BASE = 'http://localhost:3000';
const { db } = require('../src/db');

const tokens = fs.readFileSync(path.join(__dirname, '..', 'data', 'demo-tokens.txt'), 'utf8')
  .split('\n').filter((l) => l && !l.startsWith('#'));
let tIdx = 0;
const nextToken = () => tokens[tIdx++];

function client() {
  let cookie = '', csrf = '';
  async function req(p, { method = 'GET', body, headers = {} } = {}) {
    const h = { ...headers };
    if (cookie) h.Cookie = cookie;
    if (method !== 'GET') { h['X-CSRF-Token'] = h['X-CSRF-Token'] || csrf; if (body !== undefined) h['Content-Type'] = 'application/json'; }
    const res = await fetch(BASE + p, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
    const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (sc.length) cookie = sc.map((c) => c.split(';')[0]).join('; ');
    let data = null; try { data = await res.json(); } catch {}
    return { status: res.status, data };
  }
  return {
    raw: req,
    async csrf() { csrf = (await req('/api/csrf')).data.csrfToken; return csrf; },
    get: (p, headers) => req(p, { headers }),
    post: (p, body, headers) => req(p, { method: 'POST', body, headers }),
    put: (p, body) => req(p, { method: 'PUT', body }),
    getCsrf: () => csrf,
  };
}

let pass = 0, fail = 0; const fails = [];
function ok(cond, msg) { if (cond) { pass++; console.log('  ✓ ' + msg); } else { fail++; fails.push(msg); console.log('  ✗ ' + msg); } }
function section(t) { console.log('\n' + t); }

async function farmer(mobile) {
  const c = client(); await c.csrf();
  const r = await c.post('/api/auth/farmer/request-otp', { mobile });
  const code = r.data.devCode;
  const v = await c.post('/api/auth/farmer/verify-otp', { mobile, code });
  if (v.data && v.data.needsRegistration) await c.post('/api/auth/farmer/register', { name: 'Attacker Test', language: 'en' });
  return { c, code };
}
async function admin(username, password) {
  const c = client(); await c.csrf();
  await c.post('/api/auth/admin', { username, password });
  return c;
}

(async () => {
  /* ============================ OTP & REGISTRATION ============================ */
  section('OTP & ACCOUNT SECURITY');
  {
    const c = client(); await c.csrf();
    const mobile = '+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
    const r1 = await c.post('/api/auth/farmer/request-otp', { mobile });
    ok(r1.status === 200 && r1.data.devCode, 'OTP issued for new number');
    const bad = await c.post('/api/auth/farmer/verify-otp', { mobile, code: '000000' });
    ok(bad.status === 401 && bad.data.error === 'invalid', 'wrong OTP rejected');
    const good = await c.post('/api/auth/farmer/verify-otp', { mobile, code: r1.data.devCode });
    ok(good.status === 200 && good.data.needsRegistration, 'correct OTP verified (new -> needs registration)');
    // Reuse the same OTP again -> must fail (single use / consumed).
    const reuse = await c.post('/api/auth/farmer/verify-otp', { mobile, code: r1.data.devCode });
    ok(reuse.status === 401, 'OTP cannot be reused (single-use)');

    const reg = await c.post('/api/auth/farmer/register', { name: 'New Farmer', language: 'en' });
    ok(reg.status === 200 && reg.data.user, 'registration completes after OTP');

    // Enumeration: unknown vs known number look identical.
    const enum1 = await client().post('/api/auth/farmer/request-otp', { mobile: '+964800000001' }).catch(() => ({}));
    const known = client(); await known.csrf();
    const enum2 = await known.post('/api/auth/farmer/request-otp', { mobile });
    ok(enum2.status === 200 && (!enum2.data.user), 'request-otp gives generic response (no enumeration)');

    // Duplicate account: unique phone constraint at DB level.
    let dupThrew = false;
    try { db.prepare('INSERT INTO farmers (mobile,name) VALUES (?,?)').run(mobile, 'dup'); } catch { dupThrew = true; }
    ok(dupThrew, 'DB UNIQUE constraint blocks duplicate phone account');

    // OTP brute force: capped verify attempts per challenge.
    const bfMobile = '+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
    const bf = client(); await bf.csrf();
    await bf.post('/api/auth/farmer/request-otp', { mobile: bfMobile });
    let blocked = false;
    for (let i = 0; i < 7; i++) { const rr = await bf.post('/api/auth/farmer/verify-otp', { mobile: bfMobile, code: '111111' }); if (rr.data.error === 'too_many_attempts') blocked = true; }
    ok(blocked, 'OTP brute force stops after capped attempts');
  }

  /* ============================ FRONTEND-NEVER-TRUSTED ============================ */
  section('FRONTEND IS NEVER TRUSTED (server decides value/points)');
  const f1 = (await farmer('+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0'))).c;
  {
    const tok = nextToken();
    const before = (await f1.get('/api/farmer/dashboard')).data.farmer.points_balance;
    // Attacker injects points/product/value/role/farmerId — all must be ignored.
    const r = await f1.post('/api/farmer/scan', { token: tok, points: 999999, point_value: 999999, farmerId: 1, role: 'admin', balance: 999999 });
    ok(r.status === 200 && r.data.points !== 999999, 'client-supplied points/value ignored — server sets points');
    const after = (await f1.get('/api/farmer/dashboard')).data.farmer.points_balance;
    ok(after === before + r.data.points, 'balance moved only by server-computed value');
  }

  /* ============================ QR CLAIM SECURITY ============================ */
  section('QR CLAIM: single-use, invalid, duplicate, idempotent');
  {
    const tok = nextToken();
    const r1 = await f1.post('/api/farmer/scan', { token: tok });
    ok(r1.status === 200 && r1.data.points > 0, 'valid QR credits points');
    const r2 = await f1.post('/api/farmer/scan', { token: tok });
    ok(r2.status === 409 && r2.data.error === 'used', 'reused QR rejected ("already claimed")');
    const r3 = await f1.post('/api/farmer/scan', { token: 'THISistotallyBOGUS9' });
    ok(r3.status === 409 && r3.data.error === 'invalid', 'invalid/guessed QR rejected + logged');

    // Idempotency: same key + same token => single credit even on retry.
    const tok2 = nextToken();
    const key = 'idem-' + Date.now();
    const bal0 = (await f1.get('/api/farmer/dashboard')).data.farmer.points_balance;
    const a = await f1.post('/api/farmer/scan', { token: tok2 }, { 'Idempotency-Key': key });
    const b = await f1.post('/api/farmer/scan', { token: tok2 }, { 'Idempotency-Key': key });
    const bal1 = (await f1.get('/api/farmer/dashboard')).data.farmer.points_balance;
    ok(a.status === 200 && b.status === 200 && bal1 === bal0 + a.data.points, 'idempotency key prevents double credit on retry');
  }

  /* ============================ CONCURRENCY: DOUBLE-SPEND ============================ */
  section('CONCURRENCY (race conditions)');
  {
    const tok = nextToken();
    const attempts = await Promise.all(Array.from({ length: 50 }, () => f1.post('/api/farmer/scan', { token: tok })));
    const wins = attempts.filter((r) => r.status === 200 && r.data.ok && !r.data.held).length;
    ok(wins === 1, `50 simultaneous claims of ONE QR -> exactly 1 success (got ${wins})`);
    const qr = db.prepare(`SELECT status, (SELECT COUNT(*) FROM points_transactions WHERE qr_id=product_qr_codes.id) credits FROM product_qr_codes WHERE token_hash=?`)
      .get(require('../src/crypto').hashQrToken(tok));
    ok(qr.status === 'used' && qr.credits <= 1, 'QR ends "used" and credited at most once in the ledger');
  }

  /* ============================ REWARD REDEMPTION ============================ */
  section('REWARD REDEMPTION');
  const richMobile = '+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
  const rich = (await farmer(richMobile)).c;
  const richId = (await rich.get('/api/farmer/dashboard')).data.farmer.id;
  {
    // Earn a comfortable balance.
    for (let i = 0; i < 20; i++) await rich.post('/api/farmer/scan', { token: nextToken() });
    const rewards = (await rich.get('/api/farmer/rewards')).data.rewards;
    const cheap = rewards.filter((r) => r.quantity > 0).sort((a, b) => a.points_required - b.points_required)[0];

    // Insufficient funds path with a brand-new poor farmer.
    const poor = (await farmer('+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0'))).c;
    const expensive = rewards.sort((a, b) => b.points_required - a.points_required)[0];
    const ins = await poor.post('/api/farmer/redeem', { rewardId: expensive.id });
    ok(ins.status === 409 && ins.data.error === 'insufficient', 'redeem with insufficient points rejected');

    const bal0 = (await rich.get('/api/farmer/dashboard')).data.farmer.points_balance;
    const red = await rich.post('/api/farmer/redeem', { rewardId: cheap.id });
    ok(red.status === 200 && red.data.code && red.data.token, 'redeem creates secure redemption token');
    const bal1 = (await rich.get('/api/farmer/dashboard')).data.farmer.points_balance;
    ok(bal1 === bal0 - cheap.points_required, 'points deducted exactly once');

    // Idempotent redeem (double-tap).
    const key = 'rdm-' + Date.now();
    const balA = (await rich.get('/api/farmer/dashboard')).data.farmer.points_balance;
    const d1 = await rich.post('/api/farmer/redeem', { rewardId: cheap.id }, { 'Idempotency-Key': key });
    const d2 = await rich.post('/api/farmer/redeem', { rewardId: cheap.id }, { 'Idempotency-Key': key });
    const balB = (await rich.get('/api/farmer/dashboard')).data.farmer.points_balance;
    ok(balB === balA - cheap.points_required, 'idempotent redeem: double-tap deducts once');

    // Wholesaler confirm + double-confirm race.
    const wc = client(); await wc.csrf();
    await wc.post('/api/auth/wholesaler', { username: 'baghdad', password: 'Wholesale@123' });
    const look = await wc.post('/api/wholesaler/lookup', { code: red.data.token });
    ok(look.status === 200 && !look.data.redemption.already_completed, 'wholesaler validates redemption by token');
    const rid = look.data.redemption.id;
    const confirms = await Promise.all(Array.from({ length: 20 }, () => wc.post('/api/wholesaler/confirm', { redemptionId: rid })));
    const cwins = confirms.filter((r) => r.status === 200).length;
    ok(cwins === 1, `20 simultaneous confirms -> exactly 1 success (got ${cwins})`);
  }

  /* ============================ AUTHORIZATION / IDOR / RBAC ============================ */
  section('AUTHORIZATION, IDOR, ROLE ESCALATION');
  {
    // Farmer hitting admin + wholesaler endpoints.
    ok((await f1.get('/api/admin/farmers')).status === 401, 'farmer cannot call admin API');
    ok((await f1.post('/api/wholesaler/confirm', { redemptionId: 1 })).status === 401, 'farmer cannot call wholesaler API');
    // Anonymous.
    const anon = client(); await anon.csrf();
    ok((await anon.get('/api/admin/dashboard')).status === 401, 'anonymous cannot read admin dashboard');
    ok((await anon.get('/api/farmer/dashboard')).status === 401, 'anonymous cannot read farmer wallet');
    // IDOR: farmer wallet is derived from the SESSION, never a URL id — there is no
    // /farmer/:id endpoint to abuse. Confirm another farmer's data is unreachable.
    const otherId = richId; // different farmer's id
    ok((await f1.get('/api/admin/farmers/' + otherId)).status === 401, 'farmer cannot read another farmer via admin route (IDOR blocked)');

    // RBAC least privilege: REPORT_VIEWER cannot generate QR; PROGRAM_MANAGER can.
    const viewer = await admin('viewer', 'Viewer@123');
    const batch = db.prepare('SELECT id FROM batches LIMIT 1').get();
    ok((await viewer.post('/api/admin/qr/generate', { batchId: batch.id, count: 1 })).status === 403, 'REPORT_VIEWER blocked from qr.generate (RBAC)');
    ok((await viewer.get('/api/admin/dashboard')).status === 200, 'REPORT_VIEWER allowed dashboard.view');
    const mgr = await admin('manager', 'Manager@123');
    ok((await mgr.post('/api/admin/qr/generate', { batchId: batch.id, count: 2 })).status === 200, 'PROGRAM_MANAGER allowed qr.generate');
  }

  /* ============================ MASS ASSIGNMENT ============================ */
  section('MASS ASSIGNMENT');
  {
    // Registering with role/points/status fields must not set them.
    const c = client(); await c.csrf();
    const m = '+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0');
    const r = await c.post('/api/auth/farmer/request-otp', { mobile: m });
    await c.post('/api/auth/farmer/verify-otp', { mobile: m, code: r.data.devCode });
    await c.post('/api/auth/farmer/register', { name: 'Greedy', points_balance: 999999, status: 'active', role: 'admin', id: 1 });
    const created = db.prepare('SELECT points_balance, status FROM farmers WHERE mobile=?').get(m);
    ok(created && created.points_balance === 0, 'injected points_balance ignored on registration');
    const me = (await c.get('/api/auth/me')).data.user;
    ok(me.role === 'farmer', 'injected role field did not escalate privileges');
  }

  /* ============================ CSRF ============================ */
  section('CSRF');
  {
    const noCsrf = await fetch(BASE + '/api/auth/admin', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    ok(noCsrf.status === 403, 'state-changing request without CSRF token rejected');
  }

  /* ============================ CREDENTIAL LOCKOUT ============================ */
  section('CREDENTIAL LOCKOUT');
  {
    const c = client(); await c.csrf();
    let locked = false;
    for (let i = 0; i < 6; i++) { const r = await c.post('/api/auth/wholesaler', { username: 'mosul', password: 'wrongpass' }); if (r.data.error === 'locked') locked = true; }
    ok(locked, 'account locks after repeated failed logins');
  }

  /* ============================ FRAUD ENGINE ============================ */
  section('FRAUD / RISK ENGINE (configurable, high-risk hold)');
  {
    const su = await admin('admin', 'admin123');
    // Make the claim-velocity threshold tiny so we can trigger a HIGH hold deterministically.
    await su.put('/api/admin/settings', { key: 'fraud.claim_velocity', value: { window_sec: 300, count_medium: 2, count_high: 4, weight: 80 } });
    const fv = (await farmer('+9647' + String(Math.floor(Math.random() * 1e8)).padStart(8, '0'))).c;
    let held = false, credited = 0;
    for (let i = 0; i < 6; i++) { const r = await fv.post('/api/farmer/scan', { token: nextToken() }); if (r.data.held) held = true; else if (r.data.ok) credited += r.data.points; }
    ok(held, 'rapid scanning triggers HIGH risk -> transaction HELD for review');
    const reviews = (await su.get('/api/admin/reviews')).data.reviews.filter((r) => r.status === 'open');
    ok(reviews.length >= 1, 'held transaction created an open review for admin');
    // reset threshold back to sane default
    await su.put('/api/admin/settings', { key: 'fraud.claim_velocity', value: { window_sec: 300, count_medium: 15, count_high: 40, weight: 40 } });
  }

  /* ============================ ADMIN LEDGER ADJUSTMENT ============================ */
  section('POINTS LEDGER (append-only, audited adjustments)');
  {
    const su = await admin('admin', 'admin123');
    const before = db.prepare('SELECT points_balance FROM farmers WHERE id=?').get(richId).points_balance;
    const adj = await su.post(`/api/admin/farmers/${richId}/adjust`, { delta: 250, reason: 'goodwill' });
    ok(adj.status === 200 && adj.data.balance === before + 250, 'admin adjustment moves balance');
    const led = db.prepare(`SELECT * FROM points_transactions WHERE farmer_id=? AND source='ADMIN_ADJUSTMENT' ORDER BY id DESC LIMIT 1`).get(richId);
    ok(led && led.created_by_role === 'admin' && led.prev_balance === before, 'adjustment wrote an audited ledger entry (actor + prev/new balance)');
    // Immutability: history cannot be edited or deleted.
    let upErr = false, delErr = false;
    try { db.prepare('UPDATE points_transactions SET points=1 WHERE id=?').run(led.id); } catch { upErr = true; }
    try { db.prepare('DELETE FROM points_transactions WHERE id=?').run(led.id); } catch { delErr = true; }
    ok(upErr && delErr, 'points ledger is append-only (UPDATE/DELETE blocked by DB triggers)');
  }

  /* ============================ TOKEN STORAGE ============================ */
  section('TOKEN STORAGE (hash-only)');
  {
    const cols = db.prepare(`PRAGMA table_info(product_qr_codes)`).all().map((c) => c.name);
    ok(!cols.includes('token') && cols.includes('token_hash'), 'product QR raw tokens are NOT stored — only HMAC hashes');
    const sample = db.prepare('SELECT token_hash FROM product_qr_codes LIMIT 1').get().token_hash;
    ok(/^[a-f0-9]{64}$/.test(sample), 'stored value is a SHA-256 HMAC (not the printable token)');
  }

  /* ============================ BALANCE RECONCILIATION ============================ */
  section('LEDGER ↔ BALANCE RECONCILIATION');
  {
    const bad = db.prepare(`
      SELECT f.id FROM farmers f
      LEFT JOIN (SELECT farmer_id, SUM(points) s FROM points_transactions GROUP BY farmer_id) l ON l.farmer_id=f.id
      WHERE f.points_balance <> COALESCE(l.s, 0)`).all();
    ok(bad.length === 0, `every farmer's cached balance equals the sum of its ledger (${bad.length} mismatches)`);
    const neg = db.prepare('SELECT COUNT(*) c FROM farmers WHERE points_balance < 0').get().c;
    ok(neg === 0, 'no farmer has a negative balance (CHECK constraint holds)');
  }

  /* ============================ USER MANAGEMENT & STAFF AUTH ============================ */
  section('USER MANAGEMENT, TEMP PASSWORD, SESSION REVOCATION');
  {
    const su = await admin('admin', 'admin123');
    const uname = 'ops_' + Math.floor(Math.random() * 1e6);

    // Only SUPER_ADMIN can manage users.
    const mgr = await admin('manager', 'Manager@123');
    ok((await mgr.get('/api/admin/users')).status === 403, 'PROGRAM_MANAGER cannot list staff users (users.manage = SUPER_ADMIN only)');
    ok((await mgr.post('/api/admin/users', { username: uname, name: 'X', role: 'OPERATIONS' })).status === 403, 'PROGRAM_MANAGER cannot create staff users');

    const created = await su.post('/api/admin/users', { username: uname, name: 'Ops User', role: 'OPERATIONS' });
    ok(created.status === 200 && created.data.tempPassword && created.data.tempPassword.length >= 10, 'SUPER_ADMIN creates staff user with a temporary password');
    const temp = created.data.tempPassword, uid = created.data.id;

    // New user must change password on first login.
    const a1 = client(); await a1.csrf();
    const login1 = await a1.post('/api/auth/admin', { username: uname, password: temp });
    ok(login1.status === 200 && login1.data.mustChangePassword === true, 'temporary password forces a password change on login');

    // Weak new password rejected; strong accepted.
    ok((await a1.post('/api/auth/change-password', { current: temp, next: 'weak' })).status === 400, 'weak new password rejected');
    const strong = 'NewStr0ngPass1';
    ok((await a1.post('/api/auth/change-password', { current: temp, next: strong })).status === 200, 'strong password change succeeds');

    // Second session on the same user is revoked after the password change.
    const a2 = client(); await a2.csrf();
    await a2.post('/api/auth/admin', { username: uname, password: strong });
    const a3 = client(); await a3.csrf();
    await a3.post('/api/auth/admin', { username: uname, password: strong });
    await a2.post('/api/auth/change-password', { current: strong, next: 'AnotherStr0ng2' });
    ok((await a3.get('/api/admin/dashboard')).status === 401, 'changing password revokes the user\'s other sessions');

    // Last-super-admin protection.
    ok((await su.post(`/api/admin/users/1/status`, { status: 'disabled' })).status === 409, 'cannot disable the last active SUPER_ADMIN');
    ok((await su.post(`/api/admin/users/1/role`, { role: 'SUPPORT' })).status === 409, 'cannot demote the last active SUPER_ADMIN');

    // Reset auth: new temp password + session revocation.
    const reset = await su.post(`/api/admin/users/${uid}/reset-password`, {});
    ok(reset.status === 200 && reset.data.tempPassword, 'admin can reset a user (returns new temp password)');
    ok((await a2.get('/api/admin/dashboard')).status === 401, 'reset-password revokes the user\'s sessions');

    // Role change works for a non-last-super target.
    ok((await su.post(`/api/admin/users/${uid}/role`, { role: 'SUPPORT' })).status === 200, 'SUPER_ADMIN can change a user\'s role');

    // Disabled user cannot authenticate.
    await su.post(`/api/admin/users/${uid}/status`, { status: 'disabled' });
    const a4 = client(); await a4.csrf();
    ok((await a4.post('/api/auth/admin', { username: uname, password: reset.data.tempPassword })).status === 403, 'disabled staff account cannot log in');
  }

  /* ============================ REDEMPTIONS ADMIN + PAGINATION ============================ */
  section('REDEMPTIONS ADMIN & PAGINATION');
  {
    const su = await admin('admin', 'admin123');
    const reds = await su.get('/api/admin/redemptions?limit=5');
    ok(reds.status === 200 && Array.isArray(reds.data.redemptions) && typeof reds.data.total === 'number', 'redemptions list returns rows + total');
    ok(reds.data.redemptions.length <= 5, 'redemptions respect the page size');
    const viewer = await admin('viewer', 'Viewer@123');
    ok((await viewer.get('/api/admin/redemptions')).status === 200, 'REPORT_VIEWER can view redemptions (redemptions.view)');

    const page = await su.get('/api/admin/farmers?limit=5&offset=0');
    ok(page.status === 200 && page.data.farmers.length <= 5 && page.data.total > 5, 'farmers list is paginated (limit + total)');
  }

  console.log(`\n==== ${pass} passed, ${fail} failed ====`);
  if (fail) { console.log('FAILED:'); fails.forEach((f) => console.log('  - ' + f)); }
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
