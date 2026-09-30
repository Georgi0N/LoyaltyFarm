/* Farmer portal — mobile-first single-page app. */
(function () {
  'use strict';
  const root = document.getElementById('app');
  const T = App.t;
  let user = null;
  let currentView = 'home';
  let scanner = null;

  /* ------------------------------ Bootstrap ------------------------------ */
  init();
  async function init() {
    try {
      const { user: u } = await App.api('/auth/me');
      if (u && u.role === 'farmer') { user = u; renderApp(); }
      else renderAuth();
    } catch { renderAuth(); }
  }

  function langSwitch(dark) {
    return `<div class="lang-switch">
      <button data-lang="en" class="${App.lang==='en'?'active':''}">EN</button>
      <button data-lang="ar" class="${App.lang==='ar'?'active':''}">ع</button></div>`;
  }
  function wireLang(el) {
    el.querySelectorAll('[data-lang]').forEach((b) => b.onclick = () => { App.setLang(b.dataset.lang); (user?renderApp():renderAuth()); });
  }

  /* ------------------------------ Auth (OTP) ------------------------------ */
  // step: 'mobile' | 'otp' | 'register' ; ctx carries { mobile, masked, devCode }
  function renderAuth(step = 'mobile', ctx = {}) {
    const heroInner = `
      ${langSwitch()}
      <div class="auth-hero">
        <img src="/assets/img/logo.png" alt="Hasad">
        <h1>${T('brand')}</h1>
        <p>${T('tagline')}</p>
      </div>`;

    let card = '';
    if (step === 'otp') {
      card = `<h2 style="font-size:1.3rem">${T('enter_otp')}</h2>
        <p class="muted" style="margin:.3rem 0 1.2rem">${T('otp_sent_to')} <b dir="ltr">${App.esc(ctx.masked || ctx.mobile)}</b></p>
        ${ctx.devCode ? `<div class="badge badge-warn" style="margin-bottom:1rem">${T('otp_hint_dev')}: <b class="mono" style="margin-inline-start:.4rem">${App.esc(ctx.devCode)}</b></div>` : ''}
        <div class="field"><input class="input input-lg big-input mono" id="f-otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="••••••"></div>
        <button class="btn btn-primary btn-lg btn-block" id="f-verify">${T('verify')}</button>
        <div class="flex" style="margin-top:.8rem;gap:.5rem">
          <button class="btn btn-ghost" style="flex:1" id="f-resend">${T('resend_code')}</button>
          <button class="btn btn-ghost" style="flex:1" id="f-change">${T('change_number')}</button>
        </div>`;
    } else if (step === 'register') {
      card = `<h2 style="font-size:1.3rem">${T('register_title')}</h2>
        <p class="muted" style="margin:.3rem 0 1.2rem">${T('register_sub')}</p>
        <div class="field"><label>${T('full_name')}</label>
          <input class="input input-lg" id="f-name" autocomplete="name" placeholder="${T('full_name')}"></div>
        <button class="btn btn-primary btn-lg btn-block" id="f-register">${T('continue')}</button>`;
    } else {
      card = `<h2 style="font-size:1.3rem">${T('login')}</h2>
        <p class="muted" style="margin:.3rem 0 1.2rem">${T('login_farmer_sub')}</p>
        <div class="field"><label>${T('mobile_number')}</label>
          <div class="phone-row">${App.dialSelect('f-cc', ctx.cc)}
            <input class="input input-lg big-input" id="f-mobile" inputmode="tel" autocomplete="tel" dir="ltr"
              placeholder="7XX XXX XXX" value="${ctx.national||''}"></div></div>
        <button class="btn btn-primary btn-lg btn-block" id="f-send">${T('send_otp')}</button>`;
    }

    root.innerHTML = `<div class="auth phone">${heroInner}
      <div class="auth-card">${card}</div>
      <p class="muted center" style="margin-top:1.5rem;font-size:.8rem;padding:0 2rem">🔒 ${T('brand')} · ${T('tagline')}</p>
    </div>`;
    wireLang(root);

    if (step === 'otp') {
      const otp = root.querySelector('#f-otp'); otp.focus();
      const vf = (e) => App.busy(root.querySelector('#f-verify'), () => verifyOtp(ctx.mobile, otp.value.trim()), 'verify');
      root.querySelector('#f-verify').onclick = vf;
      otp.addEventListener('keydown', (e) => { if (e.key === 'Enter') vf(); });
      root.querySelector('#f-resend').onclick = (e) => App.busy(e.currentTarget, () => sendOtp(ctx.mobile), 'saving');
      root.querySelector('#f-change').onclick = () => renderAuth('mobile', { cc: ctx.cc });
    } else if (step === 'register') {
      const name = root.querySelector('#f-name'); name.focus();
      root.querySelector('#f-register').onclick = (e) => {
        if (!name.value.trim()) return App.toast(T('full_name'), 'warn');
        App.busy(e.currentTarget, () => completeRegister(name.value.trim()), 'saving');
      };
    } else {
      const m = root.querySelector('#f-mobile'); m.focus();
      const send = () => {
        const iso = root.querySelector('#f-cc').value;
        const e164 = App.composeE164(iso, m.value);
        if (!e164) return App.toast(T('mobile_number'), 'warn');
        App.busy(root.querySelector('#f-send'), () => sendOtp(e164, iso), 'saving');
      };
      root.querySelector('#f-send').onclick = send;
      m.addEventListener('keydown', (e) => { if (e.key === 'Enter') send(); });
    }
  }

  async function sendOtp(mobile, iso) {
    if (!mobile) return App.toast(T('mobile_number'), 'warn');
    try {
      const res = await App.api('/auth/farmer/request-otp', { method: 'POST', body: { mobile } });
      renderAuth('otp', { mobile, masked: mobile, devCode: res.devCode, cc: iso });
    } catch (e) {
      App.toast(T(e.data && e.data.error === 'invalid_mobile' ? 'mobile_number' : 'loading'), 'err');
    }
  }

  async function verifyOtp(mobile, code) {
    if (!code) return App.toast(T('enter_otp'), 'warn');
    try {
      const res = await App.api('/auth/farmer/verify-otp', { method: 'POST', body: { mobile, code } });
      if (res.needsRegistration) return renderAuth('register', { mobile, masked: res.mobile });
      user = res.user; App.setLang(user.language || App.lang); currentView = 'home'; renderApp();
    } catch (e) {
      const map = { invalid: 'otp_invalid', expired: 'otp_expired', too_many_attempts: 'otp_too_many', blocked: 'blocked' };
      App.toast(T(map[e.data && e.data.error] || 'otp_invalid'), 'err');
    }
  }

  async function completeRegister(name) {
    try {
      const res = await App.api('/auth/farmer/register', { method: 'POST', body: { name, language: App.lang } });
      user = res.user; App.setLang(user.language || App.lang); currentView = 'home'; renderApp();
    } catch (e) {
      if (e.data && e.data.error === 'otp_expired') { App.toast(T('otp_expired'), 'err'); renderAuth('mobile'); }
      else App.toast(T('full_name'), 'err');
    }
  }

  /* ------------------------------ App shell ------------------------------ */
  function renderApp() {
    root.innerHTML = `<div class="phone">
      <div class="f-top">
        <span class="brand"><img src="/assets/img/logo.png"><span class="brand-name">${T('brand')}</span></span>
        <span class="spacer"></span>
        ${langSwitch()}
        <button class="btn btn-ghost btn-icon" id="f-logout" title="${T('logout')}">${App.icon('logout')}</button>
      </div>
      <div class="f-content" id="f-content"></div>
      <nav class="f-nav">
        ${navBtn('home','home')}${navBtn('rewards','gift')}${navBtn('history','history')}${navBtn('account','user')}
      </nav>
    </div>`;
    wireLang(root);
    root.querySelector('#f-logout').onclick = async () => { await App.api('/auth/logout', { method: 'POST' }); App.resetCsrf(); user = null; renderAuth(); };
    root.querySelectorAll('[data-nav]').forEach((b) => b.onclick = () => go(b.dataset.nav));
    go(currentView === 'scan' || currentView === 'redemptions' ? 'home' : currentView);

    // Deep-link scan: /?c=TOKEN
    const q = new URLSearchParams(location.search);
    if (q.get('c')) { history.replaceState({}, '', '/'); go('scan'); setTimeout(() => submitCode(q.get('c')), 400); }
  }

  function navBtn(view, icon) {
    const labels = { home: 'points_balance', rewards: 'my_rewards', history: 'points_history', account: 'my_account' };
    return `<button data-nav="${view}"><span>${App.icon(icon)}</span><span>${T(labels[view])}</span></button>`;
  }
  function setActiveNav(view) {
    root.querySelectorAll('[data-nav]').forEach((b) => b.classList.toggle('active', b.dataset.nav === view));
  }

  async function go(view) {
    if (scanner) await stopScanner();
    currentView = view;
    setActiveNav(view);
    const c = root.querySelector('#f-content');
    c.innerHTML = `<div class="view">${skeleton()}</div>`;
    try {
      if (view === 'home') await viewHome(c);
      else if (view === 'scan') await viewScan(c);
      else if (view === 'rewards') await viewRewards(c);
      else if (view === 'redemptions') await viewRedemptions(c);
      else if (view === 'history') await viewHistory(c);
      else if (view === 'account') await viewAccount(c);
    } catch (e) { c.innerHTML = `<div class="empty">${App.icon('alert',40)}<p>${App.esc(e.message)}</p></div>`; }
  }
  const skeleton = () => `<div style="padding:1.15rem"><div class="skeleton" style="height:150px;border-radius:22px"></div>
    <div class="skeleton" style="height:60px;margin-top:1rem"></div><div class="skeleton" style="height:60px;margin-top:.6rem"></div></div>`;

  /* ------------------------------ Home / Dashboard ------------------------------ */
  async function viewHome(c) {
    const { farmer, stats } = await App.api('/farmer/dashboard');
    user = { ...user, ...farmer };
    c.innerHTML = `<div class="view">
      <div class="wallet">
        <div class="w-label">${T('welcome')}, ${App.esc(farmer.name.split(' ')[0])} 👋</div>
        <div class="w-label" style="margin-top:.8rem">${T('points_balance')}</div>
        <div class="w-balance">${App.num(farmer.points_balance)} <small>${T('points')}</small></div>
        <div class="w-foot">
          <div><b>${App.num(stats.scans)}</b>${T('total_scans')}</div>
          <div><b>${App.num(stats.redemptions)}</b>${T('total_redemptions')}</div>
        </div>
      </div>
      <div class="actions">
        <button class="action-btn primary" data-act="scan"><span class="a-ico">${App.icon('scan',24)}</span>${T('scan_product')}</button>
        <button class="action-btn" data-act="rewards"><span class="a-ico" style="background:var(--grad)">${App.icon('gift',24)}</span>${T('my_rewards')}</button>
        <button class="action-btn" data-act="history"><span class="a-ico" style="background:linear-gradient(135deg,#00a6c4,#0089a8)">${App.icon('history',24)}</span>${T('points_history')}</button>
        <button class="action-btn" data-act="redemptions"><span class="a-ico" style="background:linear-gradient(135deg,#9fc85a,#22a65c)">${App.icon('award',24)}</span>${T('your_redemptions')}</button>
        <button class="action-btn" data-act="account"><span class="a-ico" style="background:linear-gradient(135deg,#0e7a43,#0a5f34)">${App.icon('user',24)}</span>${T('my_account')}</button>
        <button class="action-btn" data-act="help"><span class="a-ico" style="background:linear-gradient(135deg,#00a6c4,#0089a8)">${App.icon('inbox',24)}</span>${T('help')}</button>
      </div>
    </div>`;
    c.querySelectorAll('[data-act]').forEach((b) => b.onclick = () => (b.dataset.act === 'help' ? showHelp() : go(b.dataset.act)));
  }

  function showHelp() {
    App.modal({ title: T('help_title'),
      body: `<div style="white-space:pre-line;line-height:1.9;color:var(--ink-2)">${App.esc(T('help_body'))}</div>`,
      footer: `<button class="btn btn-primary btn-block" data-close>${T('continue')}</button>` });
  }

  /* ------------------------------ Scan ------------------------------ */
  async function viewScan(c) {
    c.innerHTML = `<div class="view scan-view">
      <div class="section-head" style="padding:.4rem 0 1rem"><h2>${T('scan_title')}</h2></div>
      <p class="muted" style="margin:-.4rem 0 1rem">${T('scan_hint')}</p>
      <div id="qr-reader"><div class="scan-frame">${App.icon('camera',48)}<div style="margin-top:.6rem">${T('start_camera')}</div></div></div>
      <div class="row" style="margin-top:1rem">
        <button class="btn btn-primary btn-lg" id="cam-start" style="flex:2">${App.icon('camera')} ${T('start_camera')}</button>
        <button class="btn btn-outline btn-lg hidden" id="cam-torch" aria-label="${T('torch')}" style="flex:0 0 auto">💡</button>
      </div>
      <div class="card card-pad" style="margin-top:1.2rem">
        <label for="man-code" style="font-weight:600;font-size:.9rem">${T('enter_code_manually')}</label>
        <div class="row" style="margin-top:.5rem">
          <input class="input input-lg mono" id="man-code" style="flex:2;text-transform:uppercase" placeholder="8FK29XQ7MPL4D2A9" maxlength="20" aria-label="${T('product_code')}">
          <button class="btn btn-dark btn-lg" id="man-submit">${T('submit')}</button>
        </div>
      </div>
    </div>`;
    const startBtn = c.querySelector('#cam-start');
    startBtn.onclick = () => startScanner(startBtn);
    const manBtn = c.querySelector('#man-submit');
    manBtn.onclick = (e) => App.busy(e.currentTarget, () => submitCode(c.querySelector('#man-code').value.trim()), 'loading');
    c.querySelector('#man-code').addEventListener('keydown', (e) => { if (e.key === 'Enter') manBtn.click(); });
  }

  let scanHandled = false;
  async function startScanner(btn) {
    if (!window.Html5Qrcode) return App.toast(T('enter_code_manually'), 'warn');
    scanHandled = false;
    try {
      scanner = new Html5Qrcode('qr-reader');
      btn.disabled = true; btn.textContent = '…';
      await scanner.start({ facingMode: 'environment' }, { fps: 10, qrbox: 240 },
        (decoded) => {
          if (scanHandled) return;              // ignore duplicate callbacks from one scan
          scanHandled = true;
          const t = extractToken(decoded);
          stopScanner().then(() => submitCode(t));
        });
      btn.disabled = false; btn.innerHTML = `${App.icon('camera')} ${T('stop_camera')}`;
      btn.onclick = () => stopScanner().then(() => viewScan(root.querySelector('#f-content')));
      setupTorch();
    } catch (e) {
      btn.disabled = false; btn.innerHTML = `${App.icon('camera')} ${T('start_camera')}`;
      // Friendly, specific guidance; fall back to manual entry.
      App.toast(T('enter_code_manually'), 'warn');
    }
  }
  function setupTorch() {
    try {
      const track = scanner && scanner.getRunningTrackCapabilities ? scanner.getRunningTrackCapabilities() : null;
      const btn = root.querySelector('#cam-torch');
      if (!btn || !track || !track.torch) return;
      let on = false;
      btn.classList.remove('hidden');
      btn.onclick = async () => { on = !on; try { await scanner.applyVideoConstraints({ advanced: [{ torch: on }] }); btn.classList.toggle('btn-primary', on); } catch (e) {} };
    } catch (e) { /* torch unsupported — button stays hidden */ }
  }
  async function stopScanner() { try { if (scanner) { await scanner.stop(); scanner.clear(); } } catch(e){} scanner = null; }
  function extractToken(s) { try { const u = new URL(s); return u.searchParams.get('c') || (u.pathname.startsWith('/c/') ? u.pathname.slice(3) : s); } catch { return s; } }

  let submitting = false;
  async function submitCode(code) {
    if (!code) return App.toast(T('product_code'), 'warn');
    if (submitting) return;                 // guard against duplicate submissions
    submitting = true;
    // Idempotency key ties retries of THIS scan to one server-side result.
    const key = 'scan-' + code.toUpperCase();
    try {
      const res = await App.api('/farmer/scan', { method: 'POST', body: { token: code }, headers: { 'Idempotency-Key': key.slice(0, 100) } });
      if (res.held) { App.toast(T('scan_held'), 'warn'); return go('home'); }
      user.points_balance = res.balance;
      showScanSuccess(res.points, res.balance);
    } catch (e) {
      const map = { invalid: 'scan_again_invalid', used: 'scan_used', blocked: 'scan_blocked', ineligible: 'scan_ineligible' };
      if (e.status === 0 || e.message === 'request_failed') App.toast(T('something_wrong'), 'err');
      else App.toast(T(map[e.data && e.data.error] || 'scan_again_invalid'), 'err');
    } finally { submitting = false; }
  }
  function showScanSuccess(points, balance) {
    App.modal({
      title: '',
      body: `<div style="text-align:center;padding:.5rem 0">
        <div style="width:88px;height:88px;border-radius:50%;background:var(--grad);display:grid;place-items:center;margin:0 auto 1rem;color:#fff">${App.icon('check',44)}</div>
        <h2 style="font-size:1.5rem">${T('points_earned', { n: App.num(points) })}</h2>
        <p class="muted" style="margin:.5rem 0 0">${T('points_balance')}: <b style="color:var(--green-700)">${App.num(balance)}</b></p>
      </div>`,
      footer: `<button class="btn btn-primary btn-block" data-close>${T('continue')}</button>`,
      onOpen: (el, close) => { el.querySelector('[data-close]').onclick = () => { close(); go('home'); }; },
    });
  }

  /* ------------------------------ Rewards ------------------------------ */
  async function viewRewards(c) {
    const { balance, rewards } = await App.api('/farmer/rewards');
    c.innerHTML = `<div class="view">
      <div class="section-head"><h2>${T('rewards_catalogue')}</h2><span class="spacer"></span>
        <span class="badge badge-ok">${App.num(balance)} ${T('points')}</span></div>
      <div class="reward-list">
        ${rewards.map((r) => rewardCard(r, balance)).join('')}
      </div><div style="height:1rem"></div>
    </div>`;
    c.querySelectorAll('[data-redeem]').forEach((b) => b.onclick = () =>
      redeem(Number(b.dataset.redeem), b.dataset.name, Number(b.dataset.points), balance));
  }
  function rewardCard(r, balance) {
    const name = App.lang === 'ar' && r.name_ar ? r.name_ar : r.name;
    const desc = App.lang === 'ar' && r.description_ar ? r.description_ar : r.description;
    const can = balance >= r.points_required && r.quantity > 0;
    const short = Math.max(0, r.points_required - balance);
    // When the farmer can't afford it, show a clear progress bar + "N remaining".
    const progress = !can && r.quantity > 0
      ? `<div style="margin-top:.7rem">
           <div style="display:flex;justify-content:space-between;font-size:.8rem;color:var(--muted)">
             <span>${App.num(balance)} / ${App.num(r.points_required)}</span>
             <span><b>${App.num(short)}</b> ${T('remaining')}</span></div>
           <span class="bar" style="display:block;height:8px;background:var(--line-2);border-radius:999px;overflow:hidden;margin-top:.3rem">
             <i style="display:block;height:100%;width:${Math.min(100, balance / r.points_required * 100).toFixed(0)}%;background:var(--grad)"></i></span>
         </div>` : '';
    return `<div class="reward-card">
      <div class="reward-img">${App.icon('gift',56)}</div>
      <div class="reward-body">
        <h3>${App.esc(name)}</h3>
        <p>${App.esc(desc || '')}</p>
        <div class="reward-meta">
          <span class="reward-cost">${App.icon('coins',18)} ${App.num(r.points_required)} ${T('points')}</span>
          ${r.quantity>0 ? `<button class="btn ${can?'btn-primary':'btn-outline'}" data-redeem="${r.id}" data-name="${App.esc(name)}" data-points="${r.points_required}" ${can?'':'disabled'}>${T('redeem')}</button>`
            : `<span class="badge badge-muted">${T('out_of_stock')}</span>`}
        </div>
        ${progress}
      </div></div>`;
  }
  async function redeem(id, name, points, balance) {
    // Clear confirmation showing the balance before AND after.
    const ok = await new Promise((resolve) => App.modal({
      title: T('redeem'),
      body: `<div style="text-align:center">
          <div style="width:64px;height:64px;border-radius:16px;background:var(--grad-soft);color:var(--green-700);display:grid;place-items:center;margin:0 auto .8rem">${App.icon('gift',30)}</div>
          <h3>${App.esc(name)}</h3>
          <p class="reward-cost" style="justify-content:center;margin:.4rem 0 1rem">${App.icon('coins',18)} ${App.num(points)} ${T('points')}</p>
        </div>
        <div class="r-field" style="display:flex;justify-content:space-between;padding:.5rem 0;border-top:1px solid var(--line-2)"><span class="muted">${T('points_balance')}</span><b>${App.num(balance)}</b></div>
        <div class="r-field" style="display:flex;justify-content:space-between;padding:.5rem 0"><span class="muted">${T('balance_after')}</span><b style="color:var(--green-700)">${App.num(balance - points)}</b></div>`,
      footer: `<button class="btn btn-outline" data-no>${T('cancel')}</button><button class="btn btn-primary" data-yes>${T('redeem_now')}</button>`,
      onOpen: (el, close) => {
        el.querySelector('[data-no]').onclick = () => { close(); resolve(false); };
        el.querySelector('[data-yes]').onclick = (e) => App.busy(e.target, async () => {
          try {
            await App.api('/farmer/redeem', { method: 'POST', body: { rewardId: id } });
            close(); resolve(true);
          } catch (err) {
            const map = { insufficient: 'not_enough_points', out_of_stock: 'out_of_stock', unavailable: 'out_of_stock', review: 'scan_held' };
            App.toast(T(map[err.data && err.data.error] || 'something_wrong'), 'err');
          }
        });
      },
    }));
    if (ok) { App.toast(T('redeem_success'), 'ok'); go('redemptions'); }
  }

  /* ------------------------------ Redemptions (with QR) ------------------------------ */
  async function viewRedemptions(c) {
    const { redemptions } = await App.api('/farmer/redemptions');
    if (!redemptions.length) return empty(c, 'award', T('none_found'));
    c.innerHTML = `<div class="view">
      <div class="section-head"><h2>${T('your_redemptions')}</h2></div>
      ${redemptions.map(redemptionCard).join('')}<div style="height:1rem"></div>
    </div>`;
  }
  function redemptionCard(r) {
    const name = App.lang === 'ar' && r.reward_name_ar ? r.reward_name_ar : r.reward_name;
    const pending = r.status === 'pending';
    return `<div class="redeem-card">
      <div class="rc-head">
        <div class="a-ico" style="width:42px;height:42px;border-radius:12px;background:var(--grad-soft);color:var(--green-700);display:grid;place-items:center">${App.icon('gift')}</div>
        <div style="flex:1"><b>${App.esc(name)}</b><div class="muted" style="font-size:.8rem">${App.date(r.created_at)}</div></div>
        <span class="badge ${pending?'badge-warn':'badge-ok'}"><span class="dot"></span>${pending?T('ready_collection'):T('collected')}</span>
      </div>
      ${pending ? `<div class="rc-qr">
        <img src="${r.qr}" alt="QR">
        <div class="rc-code">${App.esc(r.code)}</div>
      </div><div class="rc-note">${T('show_this_qr')}</div>` : ''}
    </div>`;
  }

  /* ------------------------------ History ------------------------------ */
  async function viewHistory(c) {
    const { transactions } = await App.api('/farmer/transactions');
    if (!transactions.length) return empty(c, 'history', T('none_found'));
    c.innerHTML = `<div class="view"><div class="section-head"><h2>${T('points_history')}</h2></div>
      ${transactions.map((t) => {
        const earn = t.points >= 0;
        return `<div class="txn">
          <div class="t-ico ${earn?'earn':'redeem'}">${App.icon(earn?'coins':'gift')}</div>
          <div class="t-main"><b>${earn?T('earned'):T('redeemed')}</b><span>${App.esc(t.description||'')} · ${App.date(t.created_at)}</span></div>
          <div class="t-amt ${earn?'pos':'neg'}">${earn?'+':''}${App.num(t.points)}</div>
        </div>`;
      }).join('')}<div style="height:1rem"></div></div>`;
  }

  /* ------------------------------ Account ------------------------------ */
  async function viewAccount(c) {
    const f = user;
    c.innerHTML = `<div class="view">
      <div class="section-head"><h2>${T('my_account')}</h2></div>
      <div style="text-align:center;padding:1rem">
        <div style="width:80px;height:80px;border-radius:50%;background:var(--grad);display:grid;place-items:center;margin:0 auto .7rem;color:#fff">${App.icon('user',40)}</div>
        <h3>${App.esc(f.name)}</h3><p class="muted mono">${App.esc(f.mobile)}</p>
      </div>
      <div class="acc-row"><div class="a-ico">${App.icon('coins')}</div><div class="a-txt"><span>${T('points_balance')}</span><b>${App.num(f.points_balance)} ${T('points')}</b></div></div>
      <div class="acc-row"><div class="a-ico">${App.icon('user')}</div><div class="a-txt"><span>${T('mobile_number')}</span><b class="mono">${App.esc(f.mobile)}</b></div></div>
      <div class="acc-row"><div class="a-ico">${App.icon('leaf')}</div><div class="a-txt"><span>${T('language')}</span><b>${App.lang==='ar'?'العربية':'English'}</b></div>
        <div class="lang-switch">${App.lang==='ar'?'<button data-lang="en">EN</button><button class="active" data-lang="ar">ع</button>':'<button class="active" data-lang="en">EN</button><button data-lang="ar">ع</button>'}</div></div>
      <div style="padding:1.2rem 1.15rem">
        <button class="btn btn-outline btn-block btn-lg" id="acc-logout">${App.icon('logout')} ${T('logout')}</button>
      </div>
    </div>`;
    wireLang(c);
    c.querySelector('#acc-logout').onclick = async () => { await App.api('/auth/logout', { method: 'POST' }); App.resetCsrf(); user = null; renderAuth(); };
  }

  function empty(c, icon, msg) { c.innerHTML = `<div class="view"><div class="empty">${App.icon(icon,46)}<p>${App.esc(msg)}</p></div></div>`; }
})();
