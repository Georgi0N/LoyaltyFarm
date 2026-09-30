/* Wholesaler portal — validate & confirm farmer redemptions. */
(function () {
  'use strict';
  const root = document.getElementById('app');
  const T = App.t;
  let user = null, scanner = null;

  init();
  async function init() {
    try {
      const { user: u } = await App.api('/auth/me');
      if (u && u.role === 'wholesaler') { user = u; renderHome(); } else renderLogin();
    } catch { renderLogin(); }
  }

  function langSwitch() {
    return `<div class="lang-switch">
      <button data-lang="en" class="${App.lang==='en'?'active':''}">EN</button>
      <button data-lang="ar" class="${App.lang==='ar'?'active':''}">ع</button></div>`;
  }
  function wireLang(el, cb) { el.querySelectorAll('[data-lang]').forEach((b) => b.onclick = () => { App.setLang(b.dataset.lang); cb(); }); }

  /* ------------------------------ Login ------------------------------ */
  function renderLogin() {
    root.innerHTML = `<div class="login-wrap">
      <div style="display:flex;justify-content:flex-end;margin-bottom:1rem">${langSwitch()}</div>
      <div class="login-card">
        <div class="login-logo"><img src="/assets/img/logo.png"><h2>${T('wholesaler_portal')}</h2>
          <p class="muted" style="margin:.3rem 0 0">${T('wholesaler_login_sub')}</p></div>
        <div class="field"><label>${T('username')}</label><input class="input input-lg" id="w-user" autocomplete="username"></div>
        <div class="field"><label>${T('password')}</label><input class="input input-lg" id="w-pass" type="password" autocomplete="current-password"></div>
        <button class="btn btn-dark btn-lg btn-block" id="w-login">${T('login')}</button>
        <button class="btn btn-ghost btn-block" id="w-forgot" style="margin-top:.5rem;font-size:.85rem">${T('forgot_password')}</button>
      </div>
    </div>`;
    wireLang(root, renderLogin);
    const login = (e) => App.busy(root.querySelector('#w-login'), async () => {
      try {
        const res = await App.api('/auth/wholesaler', { method: 'POST',
          body: { username: root.querySelector('#w-user').value.trim(), password: root.querySelector('#w-pass').value } });
        user = res.user; user.mustChange = res.mustChangePassword; App.resetCsrf(); renderHome();
      } catch (err) {
        const map = { invalid_credentials: 'login', disabled: 'blocked', locked: 'otp_too_many' };
        App.toast(T(map[err.data && err.data.error] || 'login') + ' ✗', 'err');
      }
    }, 'loading');
    root.querySelector('#w-login').onclick = login;
    root.querySelector('#w-forgot').onclick = () => App.forgotPasswordModal('wholesaler');
    root.querySelector('#w-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
  }

  /* ------------------------------ Home ------------------------------ */
  async function renderHome() {
    root.innerHTML = `<div class="w-wrap">
      <div class="w-top">
        <span class="brand"><img src="/assets/img/logo.png" style="height:28px"><span class="brand-name">${T('brand')}</span></span>
        <span class="spacer"></span>${langSwitch()}
        <button class="btn btn-ghost btn-icon" id="w-logout">${App.icon('logout')}</button>
      </div>
      <div id="w-body"></div>
    </div>`;
    wireLang(root, renderHome);
    root.querySelector('#w-logout').onclick = async () => { await App.api('/auth/logout', { method: 'POST' }); App.resetCsrf(); user = null; renderLogin(); };
    await renderScanScreen();
    if (user.mustChange) { const ok = await App.changePasswordModal({ force: true }); if (ok) user.mustChange = false; else { await App.api('/auth/logout', { method: 'POST' }); App.resetCsrf(); user = null; renderLogin(); } }
  }

  async function renderScanScreen() {
    const body = root.querySelector('#w-body');
    body.innerHTML = skeleton();
    let summary = { wholesaler: { name: user.name }, stats: { total: 0, today: 0 } };
    try { summary = await App.api('/wholesaler/summary'); } catch {}
    body.innerHTML = `<div class="w-hero">
        <div class="muted" style="color:rgba(255,255,255,.8);font-size:.85rem">${App.esc(summary.wholesaler.name)}</div>
        <h2 style="margin-top:.2rem">${T('scan_redemption')}</h2>
        <div class="w-stats">
          <div><b>${App.num(summary.stats.total)}</b><span>${T('redemptions_total')}</span></div>
          <div><b>${App.num(summary.stats.today)}</b><span>${T('redemptions_today')}</span></div>
        </div>
      </div>
      <div style="padding:0 1.15rem">
        <div id="qr-reader" style="border-radius:22px;overflow:hidden;border:1px solid var(--line)">
          <div style="aspect-ratio:1.4;background:#0a1f16;display:grid;place-items:center;color:rgba(255,255,255,.5);text-align:center;padding:2rem">
            ${App.icon('camera',48)}<div style="margin-top:.5rem">${T('scan_redemption')}</div></div>
        </div>
        <button class="btn btn-primary btn-lg btn-block" id="cam-start" style="margin-top:1rem">${App.icon('camera')} ${T('start_camera')}</button>
        <div class="card card-pad" style="margin-top:1.2rem">
          <label style="font-weight:600;font-size:.9rem">${T('enter_code_manually')}</label>
          <div class="row" style="margin-top:.5rem">
            <input class="input input-lg mono" id="code" style="flex:2;text-transform:uppercase" placeholder="RXXX-XXXX" maxlength="40" aria-label="${T('redemption_code')}">
            <button class="btn btn-dark btn-lg" id="lookup">${T('validate')}</button>
          </div>
        </div>
        <div id="w-recent" style="margin-top:1.4rem"></div>
      </div>`;
    const startBtn = body.querySelector('#cam-start');
    startBtn.onclick = () => startScanner(startBtn);
    body.querySelector('#lookup').onclick = (e) => App.busy(e.target, () => lookup(body.querySelector('#code').value.trim()), 'loading');
    body.querySelector('#code').addEventListener('keydown', (e) => { if (e.key === 'Enter') lookup(e.target.value.trim()); });
    loadRecent();
  }

  async function loadRecent() {
    const host = root.querySelector('#w-recent'); if (!host) return;
    try {
      const { recent } = await App.api('/wholesaler/recent');
      if (!recent.length) return;
      host.innerHTML = `<div class="section-head" style="padding:.2rem 0 .6rem"><h2 style="font-size:1.05rem">${T('recent_redemptions')}</h2></div>
        ${recent.map((r) => `<div class="txn" style="border-radius:12px;border:1px solid var(--line);margin-bottom:.5rem">
          <div class="t-ico earn">${App.icon('check')}</div>
          <div class="t-main"><b>${App.esc(r.reward_name)}</b><span>${App.esc(r.farmer_name)} · ${App.esc(r.code)} · ${App.date(r.completed_at)}</span></div>
        </div>`).join('')}`;
    } catch (e) { /* non-critical */ }
  }

  async function startScanner(btn) {
    if (!window.Html5Qrcode) return App.toast('Scanner unavailable', 'err');
    try {
      scanner = new Html5Qrcode('qr-reader'); btn.disabled = true; btn.textContent = '…';
      await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 240 },
        (decoded) => stopScanner().then(() => lookup(decoded)));
      btn.disabled = false; btn.innerHTML = `${App.icon('camera')} ${T('stop_camera')}`;
      btn.onclick = () => stopScanner().then(renderScanScreen);
    } catch { btn.disabled = false; btn.innerHTML = `${App.icon('camera')} ${T('start_camera')}`; App.toast(T('enter_code_manually'), 'warn'); }
  }
  async function stopScanner() { try { if (scanner) { await scanner.stop(); scanner.clear(); } } catch(e){} scanner = null; }

  /* ------------------------------ Lookup & confirm ------------------------------ */
  async function lookup(code) {
    if (!code) return App.toast(T('product_code'), 'warn');
    await stopScanner();
    const body = root.querySelector('#w-body');
    try {
      const { redemption: r } = await App.api('/wholesaler/lookup', { method: 'POST', body: { code } });
      showResult(r);
    } catch (e) {
      body.innerHTML = `<div class="result-card">
        <div class="result-banner invalid"><div class="r-ico">${App.icon('alert',36)}</div><h2>${T('not_found')}</h2></div>
        <div class="result-body"><button class="btn btn-outline btn-block btn-lg" id="again">${T('new_lookup')}</button></div></div>`;
      body.querySelector('#again').onclick = renderScanScreen;
    }
  }

  function showResult(r) {
    const body = root.querySelector('#w-body');
    const valid = !r.already_completed;
    const name = App.lang === 'ar' && r.reward_name_ar ? r.reward_name_ar : r.reward_name;
    body.innerHTML = `<div class="result-card">
      <div class="result-banner ${valid?'valid':'invalid'}">
        <div class="r-ico">${App.icon(valid?'check':'alert',36)}</div>
        <h2>${valid?T('reward_valid'):T('reward_invalid')}</h2>
      </div>
      <div class="result-body">
        <div class="r-field"><span>${T('farmer')}</span><b>${App.esc(r.farmer_name)}</b></div>
        <div class="r-field"><span>${T('mobile')}</span><b class="mono">${App.esc(r.farmer_mobile)}</b></div>
        <div class="r-field"><span>${T('reward')}</span><b>${App.esc(name)}</b></div>
        <div class="r-field"><span>${T('redemption_code')}</span><b class="mono">${App.esc(r.code)}</b></div>
        <div class="r-field"><span>${T('status')}</span><b>${valid?App.badgeStatus('pending'):App.badgeStatus('completed')}</b></div>
        <div style="margin-top:1.2rem;display:grid;gap:.6rem">
          ${valid ? `<button class="btn btn-primary btn-lg btn-block" id="confirm">${App.icon('check')} ${T('confirm_gift_given')}</button>`
                  : `<div class="badge badge-warn" style="justify-content:center;padding:.7rem">${T('already_collected')}</div>`}
          <button class="btn btn-outline btn-block" id="again">${T('new_lookup')}</button>
        </div>
      </div></div>`;
    body.querySelector('#again').onclick = renderScanScreen;
    if (valid) body.querySelector('#confirm').onclick = async (e) => {
      // Extra confirmation prevents accidental redemption.
      const sure = await App.confirm(T('confirm_handover_title'), T('confirm_handover_prompt'));
      if (!sure) return;
      await App.busy(e.target, async () => {
        try {
          await App.api('/wholesaler/confirm', { method: 'POST', body: { redemptionId: r.id } });
          App.toast(T('gift_confirmed'), 'ok');
          showConfirmed(name, r.farmer_name);
        } catch { App.toast(T('already_collected'), 'err'); }
      });
    };
  }

  function showConfirmed(reward, farmer) {
    const body = root.querySelector('#w-body');
    body.innerHTML = `<div class="result-card">
      <div class="result-banner valid"><div class="r-ico">${App.icon('check',36)}</div><h2>${T('gift_confirmed')}</h2></div>
      <div class="result-body" style="text-align:center">
        <p style="font-size:1.05rem"><b>${App.esc(reward)}</b></p>
        <p class="muted">${App.esc(farmer)}</p>
        <button class="btn btn-primary btn-lg btn-block" id="again" style="margin-top:1rem">${T('new_lookup')}</button>
      </div></div>`;
    body.querySelector('#again').onclick = renderScanScreen;
  }

  const skeleton = () => `<div style="padding:1.15rem"><div class="skeleton" style="height:130px;border-radius:22px"></div>
    <div class="skeleton" style="height:220px;margin-top:1rem;border-radius:22px"></div></div>`;
})();
