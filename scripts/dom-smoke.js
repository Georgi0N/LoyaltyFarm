'use strict';
/**
 * Headless DOM smoke test: actually executes each portal's client JS in jsdom
 * and asserts the initial screens render (login, then a couple of authed views)
 * without throwing / logging errors. Catches runtime reference errors, bad
 * template literals, and missing globals that HTTP checks can't see.
 *
 *   node server.js                 (terminal 1)
 *   node scripts/dom-smoke.js      (terminal 2)
 */
const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const BASE = 'http://localhost:3000';
const read = (p) => fs.readFileSync(path.join(__dirname, '..', 'public', 'assets', 'js', p), 'utf8');
const i18nSrc = read('i18n.js'), commonSrc = read('common.js');

let pass = 0, fail = 0;
const ok = (c, m) => { if (c) { pass++; console.log('  ✓ ' + m); } else { fail++; console.log('  ✗ ' + m); } };

// A cookie-preserving fetch wrapper shared with the jsdom window.
function makeFetch(jar) {
  return async (url, opts = {}) => {
    const u = url.startsWith('http') ? url : BASE + url;
    const headers = Object.assign({}, opts.headers);
    if (jar.cookie) headers.Cookie = jar.cookie;
    const res = await fetch(u, { ...opts, headers });
    const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
    if (sc.length) jar.cookie = sc.map((c) => c.split(';')[0]).join('; ');
    return res;
  };
}

async function runPortal(name, jsFile, { seedLogin } = {}) {
  console.log('\n' + name.toUpperCase());
  const jar = {};
  const errors = [];
  const dom = new JSDOM(`<!DOCTYPE html><html><body><div id="app"></div></body></html>`, {
    url: BASE + '/' + name, runScripts: 'outside-only', pretendToBeVisual: true,
  });
  const { window } = dom;
  window.fetch = makeFetch(jar);
  window.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {} });
  window.scrollTo = () => {};
  window.onerror = (msg) => errors.push(String(msg));
  const origErr = console.error;

  // If this portal needs an authenticated session, log in via the real API first
  // so /auth/me returns a user and the dashboard path executes.
  if (seedLogin) { await seedLogin(makeFetch(jar), jar); }

  try {
    window.eval(i18nSrc);
    window.eval(commonSrc);
    window.eval(read(jsFile));
    // Let the async init() (fetch /auth/me) settle.
    await new Promise((r) => setTimeout(r, 800));
  } catch (e) { errors.push(e.message); }

  const appHtml = window.document.getElementById('app').innerHTML;
  ok(appHtml.length > 100, `${name}: renders content into #app`);
  ok(errors.length === 0, `${name}: no runtime errors` + (errors.length ? ' -> ' + errors[0] : ''));

  // Language switch should not throw and should re-render.
  try { window.App.setLang(window.App.lang === 'ar' ? 'en' : 'ar'); ok(true, `${name}: language switch OK`); }
  catch (e) { ok(false, `${name}: language switch threw -> ${e.message}`); }
  console.error = origErr;
  window.close();
}

async function loginAdmin(f) {
  const csrf = (await (await f('/api/csrf')).json()).csrfToken;
  await f('/api/auth/admin', { method: 'POST', headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin123' }) });
}
async function loginWholesaler(f) {
  const csrf = (await (await f('/api/csrf')).json()).csrfToken;
  await f('/api/auth/wholesaler', { method: 'POST', headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'baghdad', password: 'Wholesale@123' }) });
}

(async () => {
  // Login screens (unauthenticated).
  await runPortal('farmer', 'farmer.js');
  await runPortal('wholesaler', 'wholesaler.js');
  await runPortal('admin', 'admin.js');
  // Authenticated dashboards (exercise the real render paths).
  await runPortal('wholesaler', 'wholesaler.js', { seedLogin: loginWholesaler });
  await runPortal('admin', 'admin.js', { seedLogin: loginAdmin });

  console.log(`\n==== DOM smoke: ${pass} passed, ${fail} failed ====`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
