/* Admin dashboard — full program management. */
(function () {
  'use strict';
  const root = document.getElementById('app');
  const T = App.t;
  let user = null, current = 'dashboard';
  const charts = {};
  // [route, icon, permission required to see it]
  const NAV = [
    ['dashboard', 'home', 'dashboard.view'], ['farmers', 'users', 'farmers.view'], ['products', 'box', 'products.manage'],
    ['batches', 'layers', 'batches.manage'], ['qr_codes', 'qr', 'qr.view'], ['rewards', 'gift', 'rewards.manage'],
    ['redemptions', 'award', 'redemptions.view'], ['wholesalers', 'store', 'wholesalers.manage'],
    ['users', 'user', 'users.manage'], ['reports', 'chart', 'reports.view'],
    ['reviews', 'alert', 'reviews.manage'], ['audit_log', 'shield', 'audit.view'], ['settings', 'cog', 'settings.manage'],
  ];
  const ROUTES = { dashboard: secDashboard, farmers: secFarmers, products: secProducts, batches: secBatches,
    qr_codes: secQr, rewards: secRewards, redemptions: secRedemptions, wholesalers: secWholesalers,
    users: secUsers, reports: secReports, reviews: secReviews, audit_log: secAudit, settings: secSettings };
  const can = (perm) => user && user.permissions && (user.permissions.includes('*') || user.permissions.includes(perm));

  init();
  async function init() {
    try { const { user: u } = await App.api('/auth/me'); if (u && u.role === 'admin') { user = u; renderShell(); } else renderLogin(); }
    catch { renderLogin(); }
  }

  function langSwitch() {
    return `<div class="lang-switch"><button data-lang="en" class="${App.lang==='en'?'active':''}">EN</button>
      <button data-lang="ar" class="${App.lang==='ar'?'active':''}">ع</button></div>`;
  }

  /* ------------------------------ Login ------------------------------ */
  function renderLogin() {
    root.innerHTML = `<div class="admin-login"><div class="box">
      <div style="text-align:center;margin-bottom:1.4rem"><img src="/assets/img/logo.png"><h2>${T('admin_dashboard')}</h2></div>
      <div class="field"><label>${T('username')}</label><input class="input input-lg" id="a-user" value="admin"></div>
      <div class="field"><label>${T('password')}</label><input class="input input-lg" id="a-pass" type="password"></div>
      <div class="field hidden" id="a-mfa-field"><label>${T('mfa_code')}</label><input class="input input-lg mono" id="a-totp" inputmode="numeric" maxlength="6" placeholder="000000"></div>
      <button class="btn btn-primary btn-lg btn-block" id="a-login">${T('login')}</button>
      <p class="muted center" style="margin-top:1rem;font-size:.8rem">admin / admin123 · manager / Manager@123 · viewer / Viewer@123</p>
    </div></div>`;
    const login = async () => {
      try {
        const totp = root.querySelector('#a-totp').value.trim();
        const res = await App.api('/auth/admin', { method: 'POST',
          body: { username: root.querySelector('#a-user').value.trim(), password: root.querySelector('#a-pass').value, totp } });
        user = res.user; user.mustChange = res.mustChangePassword; App.resetCsrf(); renderShell();
      } catch (e) {
        const err = e.data && e.data.error;
        if (err === 'mfa_required' || err === 'mfa_invalid') {
          root.querySelector('#a-mfa-field').classList.remove('hidden');
          root.querySelector('#a-totp').focus();
          App.toast(T('mfa_code'), err === 'mfa_invalid' ? 'err' : 'warn');
        } else if (err === 'locked') { App.toast(T('otp_too_many') || 'locked', 'err'); }
        else App.toast(T('login') + ' ✗', 'err');
      }
    };
    root.querySelector('#a-login').onclick = login;
    root.querySelector('#a-pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
  }

  /* ------------------------------ Shell ------------------------------ */
  function renderShell() {
    root.innerHTML = `<div class="admin-shell">
      <div class="backdrop-nav" id="nav-backdrop"></div>
      <aside class="sidebar" id="sidebar">
        <div class="s-brand"><img src="/assets/img/logo.png"><b>${T('brand')}</b></div>
        <nav>${NAV.filter(([, , p]) => can(p)).map(([k, i]) => `<a data-route="${k}">${App.icon(i)}<span data-i18n="${k}">${T(k)}</span></a>`).join('')}</nav>
        <div class="s-foot">${App.esc(user.name)}<br>© 2026 Hasad Rewards</div>
      </aside>
      <div class="main">
        <div class="topbar">
          <button class="btn btn-outline btn-icon menu-btn" id="menu-btn">${App.icon('layers')}</button>
          <div><h1 id="page-title">${T('dashboard')}</h1><p class="page-sub" id="page-sub"></p></div>
          <span class="spacer"></span>${langSwitch()}
          <button class="btn btn-outline" id="a-logout">${App.icon('logout')} <span>${T('logout')}</span></button>
        </div>
        <div class="content" id="content"></div>
      </div>
    </div>`;
    root.querySelectorAll('[data-lang]').forEach((b) => b.onclick = () => { App.setLang(b.dataset.lang); renderShell(); });
    root.querySelectorAll('[data-route]').forEach((a) => a.onclick = () => { navigate(a.dataset.route); closeNav(); });
    root.querySelector('#a-logout').onclick = async () => { await App.api('/auth/logout', { method: 'POST' }); App.resetCsrf(); user = null; renderLogin(); };
    const sb = root.querySelector('#sidebar'), bd = root.querySelector('#nav-backdrop');
    root.querySelector('#menu-btn').onclick = () => { sb.classList.toggle('open'); bd.classList.toggle('show'); };
    bd.onclick = closeNav;
    function closeNav() { sb.classList.remove('open'); bd.classList.remove('show'); }
    const first = NAV.find(([, , p]) => can(p));
    if (!ROUTES[current] || !can(NAV.find(([k]) => k === current)[2])) current = first ? first[0] : 'dashboard';
    navigate(current);
    // Force a password change when signing in with a temporary password.
    if (user.mustChange) {
      App.changePasswordModal({ force: true }).then((ok) => {
        if (ok) user.mustChange = false;
        else root.querySelector('#a-logout').click();
      });
    }
  }

  async function navigate(route) {
    const navItem = NAV.find(([k]) => k === route);
    if (navItem && !can(navItem[2])) { App.toast(T('forbidden') || 'forbidden', 'err'); return; }
    current = route;
    root.querySelectorAll('[data-route]').forEach((a) => a.classList.toggle('active', a.dataset.route === route));
    root.querySelector('#page-title').textContent = T(route === 'audit_log' ? 'audit_log' : route);
    root.querySelector('#page-sub').textContent = route === 'dashboard' ? T('overview') : '';
    const c = root.querySelector('#content');
    Object.values(charts).forEach((ch) => ch && ch.destroy());
    c.innerHTML = `<div class="stat-grid">${Array(4).fill('<div class="skeleton" style="height:110px"></div>').join('')}</div>`;
    try { await ROUTES[route](c); } catch (e) { c.innerHTML = `<div class="empty">${App.icon('alert',44)}<p>${App.esc(e.message)}</p></div>`; }
  }

  /* helpers */
  const statCard = (icon, val, label, sub) => `<div class="stat">
    <div class="stat-ico">${App.icon(icon)}</div>
    <div class="stat-val mono">${val}</div><div class="stat-label">${label}</div>${sub?`<div class="stat-sub muted">${sub}</div>`:''}</div>`;
  const initials = (n) => n.split(' ').map((x) => x[0]).slice(0, 2).join('').toUpperCase();
  function cardWrap(title, inner, headExtra) { return `<div class="card"><div class="card-head"><h3>${title}</h3><span class="spacer"></span>${headExtra||''}</div><div>${inner}</div></div>`; }

  /* ------------------------------ Dashboard ------------------------------ */
  async function secDashboard(c) {
    const { stats, charts: ch } = await App.api('/admin/dashboard');
    c.innerHTML = `
      <div class="stat-grid">
        ${statCard('users', App.num(stats.farmers), T('total_farmers'))}
        ${statCard('leaf', App.num(stats.activeFarmers), T('active_farmers'))}
        ${statCard('scan', App.num(stats.scans), T('total_scans_s'))}
        ${statCard('coins', App.num(stats.pointsIssued), T('points_issued'))}
        ${statCard('gift', App.num(stats.rewardsRedeemed), T('rewards_redeemed'))}
        ${statCard('qr', App.num(stats.qrActive), T('active_qr'))}
        ${statCard('check', App.num(stats.qrUsed), T('used_qr'))}
        ${statCard('alert', App.num(stats.suspicious), T('suspicious_scans'))}
      </div>
      <div class="section-title"><h2>${T('program_performance')}</h2></div>
      <div class="chart-grid">
        <div class="card card-pad"><h3 style="font-size:.98rem;margin-bottom:.5rem">${T('scans_registrations')}</h3><div class="chart-box"><canvas id="ch-trend"></canvas></div></div>
        <div class="card card-pad"><h3 style="font-size:.98rem;margin-bottom:.5rem">${T('qr_usage')}</h3><div class="chart-box"><canvas id="ch-qr"></canvas></div></div>
        <div class="card card-pad"><h3 style="font-size:.98rem;margin-bottom:.5rem">${T('top_products')}</h3><div class="chart-box"><canvas id="ch-prod"></canvas></div></div>
        <div class="card card-pad"><h3 style="font-size:.98rem;margin-bottom:.5rem">${T('top_rewards')}</h3><div class="chart-box"><canvas id="ch-rew"></canvas></div></div>
      </div>`;

    const days = mergeDays(ch.scansByDay, ch.regsByDay);
    charts.trend = new Chart('ch-trend', { type: 'line',
      data: { labels: days.labels, datasets: [
        lineDs(T('scans'), days.scans, '#22a65c'), lineDs(T('farmers'), days.regs, '#00a6c4') ] },
      options: baseOpts() });
    charts.qr = new Chart('ch-qr', { type: 'doughnut',
      data: { labels: [T('active_qr'), T('used_qr')], datasets: [{ data: [stats.qrActive, stats.qrUsed],
        backgroundColor: ['#9fc85a', '#00a6c4'], borderWidth: 0 }] },
      options: { ...baseOpts(), cutout: '62%', scales: {} } });
    charts.prod = barChart('ch-prod', ch.topProducts.map((p) => p.name), ch.topProducts.map((p) => p.c), '#22a65c');
    charts.rew = barChart('ch-rew', ch.topRewards.map((p) => p.name), ch.topRewards.map((p) => p.c), '#0089a8');
  }

  /* ------------------------------ Farmers ------------------------------ */
  async function secFarmers(c) {
    const render = async (q, offset = 0) => {
      const qs = `?limit=25&offset=${offset}` + (q ? `&q=${encodeURIComponent(q)}` : '');
      const { farmers, total, limit } = await App.api('/admin/farmers' + qs);
      body.innerHTML = `<div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('name')}</th><th>${T('mobile')}</th><th>${T('reg_date')}</th><th>${T('balance')}</th>
        <th>${T('redemptions')}</th><th>${T('status')}</th><th>${T('actions')}</th></tr></thead><tbody>
        ${farmers.map((f) => `<tr>
          <td><span class="chip"><span class="avatar">${initials(f.name)}</span>${App.esc(f.name)}</span></td>
          <td class="mono">${App.esc(f.mobile)}</td><td>${App.date(f.created_at)}</td>
          <td class="mono"><b>${App.num(f.points_balance)}</b></td><td>${App.num(f.redemptions)}</td>
          <td>${App.badgeStatus(f.status)}</td>
          <td><div class="flex gap-sm">
            <button class="btn btn-sm btn-outline" data-view="${f.id}">${T('view')}</button>
            <button class="btn btn-sm ${f.status==='active'?'btn-danger':'btn-outline'}" data-toggle="${f.id}" data-status="${f.status}">${f.status==='active'?T('block'):T('unblock')}</button>
          </div></td></tr>`).join('') || emptyRow(7)}
      </tbody></table></div>`;
      body.appendChild(App.pager(total, limit, offset, (o) => render(q, o)));
      body.querySelectorAll('[data-view]').forEach((b) => b.onclick = () => farmerDetail(b.dataset.view));
      body.querySelectorAll('[data-toggle]').forEach((b) => b.onclick = async () => {
        const ns = b.dataset.status === 'active' ? 'blocked' : 'active';
        await App.api(`/admin/farmers/${b.dataset.toggle}/status`, { method: 'POST', body: { status: ns } });
        App.toast(T('save'), 'ok'); render(searchInput.value.trim(), offset);
      });
    };
    c.innerHTML = `<div class="toolbar">
      <div class="search-box">${App.icon('search',18)}<input class="input" id="f-search" placeholder="${T('search')}…" aria-label="${T('search')}"></div>
    </div><div id="f-body"></div>`;
    const body = c.querySelector('#f-body'); const searchInput = c.querySelector('#f-search');
    let tmr; searchInput.oninput = () => { clearTimeout(tmr); tmr = setTimeout(() => render(searchInput.value.trim()), 250); };
    await render('');
  }
  async function farmerDetail(id) {
    const { farmer, transactions, redemptions } = await App.api('/admin/farmers/' + id);
    App.modal({ title: farmer.name, body: `
      <div class="flex gap wrap" style="margin-bottom:1rem">
        <span class="badge badge-info">${App.esc(farmer.mobile)}</span>
        <span class="badge badge-ok">${App.num(farmer.points_balance)} ${T('points')}</span>
        ${App.badgeStatus(farmer.status)}</div>
      <h4 style="margin:.5rem 0">${T('transaction_history')}</h4>
      <div class="table-wrap" style="max-height:240px;overflow:auto"><table class="data"><tbody>
        ${transactions.map((t) => `<tr><td>${App.esc(t.description||'')}<br><small class="muted">${App.date(t.created_at)}</small></td>
          <td class="mono" style="text-align:end;color:${t.points>=0?'var(--green-700)':'var(--teal-700)'}"><b>${t.points>=0?'+':''}${App.num(t.points)}</b></td></tr>`).join('') || emptyRow(2)}
      </tbody></table></div>
      <h4 style="margin:1rem 0 .5rem">${T('rewards_redeemed')}</h4>
      <div class="table-wrap"><table class="data"><tbody>
        ${redemptions.map((r) => `<tr><td>${App.esc(r.reward_name)}<br><small class="muted mono">${App.esc(r.code)}</small></td>
          <td style="text-align:end">${App.badgeStatus(r.status)}</td></tr>`).join('') || emptyRow(2)}
      </tbody></table></div>`,
      footer: `${can('farmers.adjust') ? `<button class="btn btn-outline" data-adjust>${T('adjust_points')}</button>` : ''}
               <button class="btn btn-primary" data-close>${T('close')}</button>`,
      onOpen: (el, close) => {
        const adj = el.querySelector('[data-adjust]');
        if (adj) adj.onclick = () => { close(); adjustPointsModal(farmer); };
      } });
  }

  function adjustPointsModal(farmer) {
    formModal(`${T('adjust_points')} — ${farmer.name}`, [
      { name: 'delta', label: T('amount'), type: 'number', placeholder: 'e.g. 200 or -100', required: true },
      { name: 'reason', label: T('reason'), required: true },
    ], async (v) => {
      await App.api(`/admin/farmers/${farmer.id}/adjust`, { method: 'POST', body: v });
      navigate('farmers');
    }, `${T('points_balance')}: ${App.num(farmer.points_balance)} — ${T('audit_log')}: every adjustment is logged.`);
  }

  /* ------------------------------ Fraud Reviews ------------------------------ */
  async function secReviews(c) {
    const { reviews } = await App.api('/admin/reviews');
    c.innerHTML = `<div class="table-wrap card"><table class="data"><thead><tr>
      <th>${T('farmer')}</th><th>${T('kind')}</th><th>${T('risk_score')}</th><th>${T('reasons')}</th>
      <th>${T('status')}</th><th>${T('created')}</th><th>${T('actions')}</th></tr></thead><tbody>
      ${reviews.map((r) => `<tr>
        <td><span class="chip"><span class="avatar" style="background:linear-gradient(135deg,#e5484d,#b03236)">${initials(r.farmer_name)}</span>${App.esc(r.farmer_name)}</span></td>
        <td>${App.esc(r.kind)}</td><td><span class="badge ${r.risk_score>=70?'badge-danger':'badge-warn'}">${r.risk_score}</span></td>
        <td class="muted" style="font-size:.8rem;max-width:260px">${App.esc((JSON.parse(r.reasons||'[]')).join(', '))}</td>
        <td>${App.badgeStatus(r.status)}</td><td class="muted">${App.date(r.created_at)}</td>
        <td>${r.status==='open'?`<div class="flex gap-sm">
          <button class="btn btn-sm btn-primary" data-approve="${r.id}">${T('approve')}</button>
          <button class="btn btn-sm btn-danger" data-reject="${r.id}">${T('reject')}</button></div>`:'—'}</td>
      </tr>`).join('') || emptyRow(7)}
    </tbody></table></div>`;
    c.querySelectorAll('[data-approve]').forEach((b) => b.onclick = async () => {
      await App.api(`/admin/reviews/${b.dataset.approve}/approve`, { method: 'POST' }); App.toast(T('approve') + ' ✓', 'ok'); navigate('reviews');
    });
    c.querySelectorAll('[data-reject]').forEach((b) => b.onclick = async () => {
      await App.api(`/admin/reviews/${b.dataset.reject}/reject`, { method: 'POST' }); App.toast(T('reject'), 'warn'); navigate('reviews');
    });
  }

  /* ------------------------------ Products & SKUs ------------------------------ */
  async function secProducts(c) {
    const { products, skus } = await App.api('/admin/products');
    const skuByProduct = (pid) => skus.filter((s) => s.product_id === pid);
    c.innerHTML = `<div class="toolbar"><span class="spacer"></span>
      <button class="btn btn-outline" id="add-sku">${App.icon('plus')} ${T('add_sku')}</button>
      <button class="btn btn-primary" id="add-prod">${App.icon('plus')} ${T('add_product')}</button></div>
      <div class="grid" style="gap:1rem">
        ${products.map((p) => cardWrap(`${App.esc(p.name)} <span class="badge badge-muted">${App.esc(p.category||'')}</span>`,
          `<div class="table-wrap"><table class="data"><thead><tr><th>${T('sku')}</th><th>${T('size')}</th><th>${T('point_value')}</th><th>${T('status')}</th></tr></thead>
          <tbody>${skuByProduct(p.id).map((s) => `<tr><td class="mono">${App.esc(s.sku_code)}</td><td>${App.esc(s.size_label||'')}</td>
            <td><b>${App.num(s.default_points)}</b></td><td>${App.badgeStatus(s.status)}</td></tr>`).join('') || emptyRow(4)}</tbody></table></div>`,
          App.badgeStatus(p.status))).join('') || `<div class="empty">${App.icon('box',44)}<p>${T('none_found')}</p></div>`}
      </div>`;
    c.querySelector('#add-prod').onclick = () => formModal(T('add_product'), [
      { name: 'name', label: T('product_name'), required: true },
      { name: 'category', label: T('category') },
    ], async (v) => { await App.api('/admin/products', { method: 'POST', body: v }); navigate('products'); });
    c.querySelector('#add-sku').onclick = () => formModal(T('add_sku'), [
      { name: 'productId', label: T('product_name'), type: 'select', options: products.map((p) => [p.id, p.name]), required: true },
      { name: 'skuCode', label: T('sku'), required: true },
      { name: 'sizeLabel', label: T('size') },
      { name: 'defaultPoints', label: T('point_value'), type: 'number' },
    ], async (v) => { await App.api('/admin/skus', { method: 'POST', body: v }); navigate('products'); });
  }

  /* ------------------------------ Batches ------------------------------ */
  async function secBatches(c) {
    const [{ batches }, { products, skus }] = await Promise.all([App.api('/admin/batches'), App.api('/admin/products')]);
    c.innerHTML = `<div class="toolbar"><span class="spacer"></span>
      <button class="btn btn-primary" id="add-batch">${App.icon('plus')} ${T('create_batch')}</button></div>
      <div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('batch_number')}</th><th>${T('product_name')}</th><th>${T('sku')}</th><th>${T('point_value')}</th>
        <th>${T('production_date')}</th><th>${T('expiry_date')}</th><th>${T('qr_generated')}</th><th>${T('used')}</th></tr></thead><tbody>
        ${batches.map((b) => `<tr><td class="mono"><b>${App.esc(b.batch_number)}</b></td><td>${App.esc(b.product_name)}</td>
          <td class="mono">${App.esc(b.sku_code)}</td><td>${App.num(b.point_value)}</td><td>${App.date(b.production_date)}</td>
          <td>${App.date(b.expiry_date)}</td><td><b>${App.num(b.qr_count)}</b></td>
          <td><span class="badge badge-ok">${App.num(b.used)}</span></td></tr>`).join('') || emptyRow(8)}
      </tbody></table></div>`;
    c.querySelector('#add-batch').onclick = () => formModal(T('create_batch'), [
      { name: 'skuId', label: T('sku'), type: 'select', required: true,
        options: skus.map((s) => [s.id, `${s.sku_code} — ${(products.find((p) => p.id === s.product_id)||{}).name || ''}`]) },
      { name: 'batchNumber', label: T('batch_number'), placeholder: 'IRQ-SEP-2026-04', required: true },
      { name: 'pointValue', label: T('point_value'), type: 'number' },
      { name: 'productionDate', label: T('production_date'), type: 'date' },
      { name: 'expiryDate', label: T('expiry_date'), type: 'date' },
    ], async (v) => { await App.api('/admin/batches', { method: 'POST', body: v }); navigate('batches'); });
  }

  /* ------------------------------ QR Codes ------------------------------ */
  async function secQr(c) {
    const [{ batches }, st] = await Promise.all([App.api('/admin/qr/batches'), App.api('/admin/dashboard')]);
    const canExport = can('qr.export'), canGen = can('qr.generate'), canBlock = can('qr.block');
    c.innerHTML = `<div class="stat-grid" style="margin-bottom:1.4rem">
        ${statCard('qr', App.num(st.stats.qrTotal), T('generated'))}
        ${statCard('leaf', App.num(st.stats.qrActive), T('unused'))}
        ${statCard('check', App.num(st.stats.qrUsed), T('used'))}
        ${statCard('shield', App.num(st.stats.qrTotal - st.stats.qrActive - st.stats.qrUsed), T('blocked'))}
      </div>
      <div class="section-title"><h2>${T('qr_batches')}</h2><span class="spacer"></span>
        ${canGen ? `<button class="btn btn-primary" id="qr-gen">${App.icon('plus')} ${T('generate_qr')}</button>` : ''}</div>
      <div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('batch_number')}</th><th>${T('product_name')}</th><th>${T('sku')}</th><th>${T('point_value')}</th>
        <th>${T('total_codes')}</th><th>${T('unused')}</th><th>${T('used')}</th>${canExport?`<th>${T('actions')}</th>`:''}</tr></thead><tbody>
        ${batches.map((b) => `<tr>
          <td class="mono"><b>${App.esc(b.batch_number)}</b></td><td>${App.esc(b.product_name)}</td><td class="mono">${App.esc(b.sku_code)}</td>
          <td>${App.num(b.point_value)}</td><td><b>${App.num(b.total)}</b></td><td>${App.num(b.unused)}</td><td>${App.num(b.used)}</td>
          ${canExport?`<td><div class="flex gap-sm wrap">
            <button class="btn btn-sm btn-primary" data-preview="${b.id}" data-total="${b.total}">${App.icon('qr',15)} ${T('preview')}</button>
          </div></td>`:''}
        </tr>`).join('') || emptyRow(canExport?8:7)}
      </tbody></table></div>
      <p class="muted" style="margin:.7rem 0 0;font-size:.82rem">🔒 Tokens are encrypted at rest — print/export happens only here, through your authenticated session, and every export is audited.</p>
      <div class="section-title"><h2>${T('qr_codes')}</h2></div>
      <div class="toolbar">
        <select class="select" id="qr-batch" style="max-width:280px"><option value="">${T('all')} — ${T('batches')}</option>
          ${batches.map((b) => `<option value="${b.id}">${App.esc(b.batch_number)} (${App.esc(b.product_name)})</option>`).join('')}</select>
        <select class="select" id="qr-status" style="max-width:160px">
          <option value="">${T('all')}</option><option value="unused">${T('unused')}</option>
          <option value="used">${T('used')}</option><option value="blocked">${T('blocked')}</option></select>
      </div><div id="qr-body"></div>`;

    c.querySelectorAll('[data-preview]').forEach((b) => b.onclick = () => qrPreview(Number(b.dataset.preview), Number(b.dataset.total)));
    const gen = c.querySelector('#qr-gen');
    if (gen) gen.onclick = () => formModal(T('generate_qr'), [
      { name: 'batchId', label: T('batch_number'), type: 'select', required: true, options: batches.map((b) => [b.id, `${b.batch_number} — ${b.product_name}`]) },
      { name: 'count', label: T('how_many'), type: 'number', placeholder: '50000', required: true },
    ], async (v) => { const r = await App.api('/admin/qr/generate', { method: 'POST', body: v });
      App.toast(`${App.num(r.generated)} ${T('qr_codes')} ✓`, 'ok'); navigate('qr_codes'); }, T('bulk_gen_hint'));

    const batchSel = c.querySelector('#qr-batch'), statusSel = c.querySelector('#qr-status'), body = c.querySelector('#qr-body');
    const load = async (offset = 0) => {
      const params = new URLSearchParams({ limit: '50', offset: String(offset) });
      if (batchSel.value) params.set('batchId', batchSel.value);
      if (statusSel.value) params.set('status', statusSel.value);
      const { codes, total, limit } = await App.api('/admin/qr?' + params.toString());
      body.innerHTML = `<div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('token')} (HMAC)</th><th>${T('product_name')}</th><th>${T('sku')}</th><th>${T('batch_number')}</th>
        <th>${T('point_value')}</th><th>${T('status')}</th>${canBlock?`<th>${T('actions')}</th>`:''}</tr></thead><tbody>
        ${codes.map((q) => `<tr><td class="mono muted"><b>${App.esc(q.token_ref)}…</b></td><td>${App.esc(q.product_name)}</td>
          <td class="mono">${App.esc(q.sku_code)}</td><td class="mono">${App.esc(q.batch_number)}</td>
          <td>${App.num(q.point_value)}</td><td>${App.badgeStatus(q.status)}</td>
          ${canBlock?`<td>${q.status==='unused'?`<button class="btn btn-sm btn-outline" data-block="${q.id}">${T('block_qr')}</button>`:'—'}</td>`:''}</tr>`).join('') || emptyRow(canBlock?7:6)}
      </tbody></table></div><div id="qr-pager"></div>`;
      body.querySelector('#qr-pager').appendChild(App.pager(total, limit, offset, load));
      body.querySelectorAll('[data-block]').forEach((b) => b.onclick = async () => {
        await App.api(`/admin/qr/${b.dataset.block}/block`, { method: 'POST' }); App.toast(T('save'), 'ok'); load(offset);
      });
    };
    batchSel.onchange = () => load(0); statusSel.onchange = () => load(0);
    await load();
  }

  // Secure preview + print/export dialog for one batch.
  function qrPreview(batchId, total) {
    let from = 1, per = 25, encode = 'url';
    const clamp = () => { per = Math.min(100, per); from = Math.max(1, Math.min(from, Math.max(1, total - per + 1))); };
    const { close } = App.modal({
      title: T('preview_labels'),
      body: `<div id="qp"></div>`,
      footer: `<button class="btn btn-outline" data-close>${T('close')}</button>`,
      onOpen: (el) => { render(el.querySelector('#qp')); },
    });
    async function render(host) {
      clamp();
      const to = Math.min(total, from + per - 1);
      host.innerHTML = `<div class="flex gap wrap items-center" style="margin-bottom:1rem">
          <label class="muted" style="font-size:.85rem">${T('from')}</label><input class="input" id="qp-from" type="number" value="${from}" style="width:90px">
          <label class="muted" style="font-size:.85rem">${T('per_page')}</label>
          <select class="select" id="qp-per" style="width:90px">${[10,25,50,100].map((n)=>`<option ${n===per?'selected':''}>${n}</option>`).join('')}</select>
          <label class="muted" style="font-size:.85rem">${T('encode')}</label>
          <select class="select" id="qp-enc" style="width:130px"><option value="url" ${encode==='url'?'selected':''}>${T('scan_link')}</option><option value="token" ${encode==='token'?'selected':''}>${T('raw_token')}</option></select>
        </div>
        <div id="qp-grid" class="grid" style="grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:.7rem">${T('loading_labels')}</div>
        <div class="pager" id="qp-pager"></div>
        <div class="flex gap wrap" style="margin-top:1rem;justify-content:center">
          <button class="btn btn-dark" id="qp-print">${App.icon('qr')} ${T('print')}</button>
          <button class="btn btn-outline" id="qp-pdf">${App.icon('download')} ${T('download_pdf')}</button>
          <button class="btn btn-outline" id="qp-zip">${App.icon('download')} ${T('download_zip')}</button>
          <button class="btn btn-outline" id="qp-csv">${App.icon('download')} ${T('export_csv')}</button>
        </div>
        <p class="muted center" style="font-size:.78rem;margin-top:.6rem">${T('total_codes')}: ${App.num(total)} · ${T('labels')} ${App.num(from)}–${App.num(to)}</p>`;
      host.querySelector('#qp-from').onchange = (e) => { from = parseInt(e.target.value, 10) || 1; render(host); };
      host.querySelector('#qp-per').onchange = (e) => { per = parseInt(e.target.value, 10) || 25; from = 1; render(host); };
      host.querySelector('#qp-enc').onchange = (e) => { encode = e.target.value; render(host); };
      host.querySelector('#qp-pager').appendChild(App.pager(total, per, from - 1, (o) => { from = o + 1; render(host); }));
      // Print opens the secure server-rendered print page in a new tab.
      host.querySelector('#qp-print').onclick = () => window.open(`/admin/print/qr/${batchId}?from=${from}&to=${to}&cols=3&encode=${encode}`, '_blank');
      host.querySelector('#qp-pdf').onclick = (e) => exportBatch(e.currentTarget, batchId, 'pdf', from, to, encode);
      host.querySelector('#qp-zip').onclick = (e) => exportBatch(e.currentTarget, batchId, 'zip', from, to, encode);
      host.querySelector('#qp-csv').onclick = (e) => exportBatch(e.currentTarget, batchId, 'csv', from, to, encode);
      try {
        const data = await App.api(`/admin/qr/batches/${batchId}/labels?from=${from}&to=${to}&encode=${encode}`);
        host.querySelector('#qp-grid').innerHTML = data.labels.map((l) => `<div style="text-align:center">
          <img src="${l.qr}" alt="QR ${l.seq}" style="width:100%;border:1px solid var(--line-2);border-radius:8px">
          <div class="mono muted" style="font-size:.68rem;margin-top:2px">#${App.num(l.seq)} · ${App.esc(l.token_ref)}</div></div>`).join('');
      } catch (e) { host.querySelector('#qp-grid').innerHTML = `<p class="muted">${T(e.data && e.data.error === 'invalid_range' ? 'range_invalid' : 'something_wrong')}</p>`; }
    }
    async function exportBatch(btn, id, fmt, from, to, encode) {
      const size = to - from + 1;
      // Large exports require a fresh re-auth (password, and MFA if enabled).
      if (size > 5000) {
        const okAuth = await reauthPrompt();
        if (!okAuth) return;
      }
      const url = `/api/admin/qr/batches/${id}/export/${fmt}?from=${from}&to=${to}&encode=${encode}&cols=3`;
      // Probe with fetch to surface auth/errors, then trigger the download.
      await App.busy(btn, async () => {
        const res = await fetch(url, { credentials: 'same-origin' });
        if (res.status === 401) { const d = await res.json().catch(() => ({})); return App.toast(T(d.error === 'reauth_required' ? 'reauth_required' : 'something_wrong'), 'err'); }
        if (!res.ok) return App.toast(T('something_wrong'), 'err');
        const blob = await res.blob();
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = `${fmt}_batch_${id}_${from}-${to}.${fmt}`; document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      });
    }
  }

  function reauthPrompt() {
    return new Promise((resolve) => App.modal({
      title: T('reauth_title'),
      body: `<p class="muted">${T('reauth_prompt')}</p>
        <div class="field"><label>${T('password')}</label><input class="input" type="password" id="ra-pw" autocomplete="current-password"></div>
        <div class="field"><label>${T('mfa_code')} <span class="muted">(${T('inactive')})</span></label><input class="input mono" id="ra-totp" inputmode="numeric" maxlength="6" placeholder="000000"></div>`,
      footer: `<button class="btn btn-outline" data-no>${T('cancel')}</button><button class="btn btn-primary" data-yes>${T('confirm')}</button>`,
      onOpen: (el, close) => {
        el.querySelector('[data-no]').onclick = () => { close(); resolve(false); };
        el.querySelector('[data-yes]').onclick = (e) => App.busy(e.target, async () => {
          try { await App.api('/admin/qr/reauth', { method: 'POST', body: { password: el.querySelector('#ra-pw').value, totp: el.querySelector('#ra-totp').value.trim() } });
            close(); resolve(true); }
          catch (err) { App.toast(T('wrong_current'), 'err'); }
        });
      },
    }));
  }

  /* ------------------------------ Rewards ------------------------------ */
  async function secRewards(c) {
    const { rewards } = await App.api('/admin/rewards');
    c.innerHTML = `<div class="toolbar"><span class="spacer"></span>
      <button class="btn btn-primary" id="add-reward">${App.icon('plus')} ${T('add_reward')}</button></div>
      <div class="stat-grid" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr))">
        ${rewards.map((r) => `<div class="card">
          <div class="reward-img" style="height:110px;background:var(--grad-soft);color:var(--green-700);display:grid;place-items:center;border-radius:16px 16px 0 0">${App.icon('gift',48)}</div>
          <div class="card-pad">
            <div class="flex items-center gap-sm"><h3 style="font-size:1.02rem;flex:1">${App.esc(r.name)}</h3>${App.badgeStatus(r.status)}</div>
            <p class="muted" style="font-size:.84rem;margin:.4rem 0">${App.esc(r.description||'')}</p>
            <div class="flex items-center" style="justify-content:space-between;margin-top:.6rem">
              <span class="reward-cost" style="font-weight:800;color:var(--green-700)">${App.num(r.points_required)} ${T('points')}</span>
              <span class="badge ${r.quantity>0?'badge-info':'badge-danger'}">${App.num(r.quantity)} ${T('available')}</span></div>
            <button class="btn btn-sm btn-outline btn-block" style="margin-top:.8rem" data-toggle="${r.id}" data-status="${r.status}">
              ${r.status==='active'?T('inactive'):T('active')}</button>
          </div></div>`).join('') || `<div class="empty">${App.icon('gift',44)}<p>${T('none_found')}</p></div>`}
      </div>`;
    c.querySelectorAll('[data-toggle]').forEach((b) => b.onclick = async () => {
      const ns = b.dataset.status === 'active' ? 'inactive' : 'active';
      await App.api(`/admin/rewards/${b.dataset.toggle}/status`, { method: 'POST', body: { status: ns } }); navigate('rewards');
    });
    c.querySelector('#add-reward').onclick = () => formModal(T('add_reward'), [
      { name: 'name', label: T('reward_name'), required: true },
      { name: 'nameAr', label: T('reward_name_ar') },
      { name: 'description', label: T('description'), type: 'textarea' },
      { name: 'pointsRequired', label: T('points_required'), type: 'number', required: true },
      { name: 'quantity', label: T('quantity'), type: 'number', required: true },
    ], async (v) => { await App.api('/admin/rewards', { method: 'POST', body: v }); navigate('rewards'); });
  }

  /* ------------------------------ Wholesalers ------------------------------ */
  async function secWholesalers(c) {
    const { wholesalers } = await App.api('/admin/wholesalers');
    c.innerHTML = `<div class="toolbar"><span class="spacer"></span>
      <button class="btn btn-primary" id="add-w">${App.icon('plus')} ${T('add_wholesaler')}</button></div>
      <div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('name')}</th><th>${T('location')}</th><th>${T('contact')}</th><th>${T('username')}</th>
        <th>${T('total_redeems')}</th><th>${T('status')}</th><th>${T('actions')}</th></tr></thead><tbody>
        ${wholesalers.map((w) => `<tr>
          <td><span class="chip"><span class="avatar" style="background:linear-gradient(135deg,#00a6c4,#0089a8)">${initials(w.name)}</span>${App.esc(w.name)}</span></td>
          <td>${App.esc(w.location||'')}</td><td class="mono">${App.esc(w.contact||'')}</td><td class="mono">${App.esc(w.username)}</td>
          <td><b>${App.num(w.redemptions)}</b></td><td>${App.badgeStatus(w.status)}</td>
          <td><div class="flex gap-sm wrap">
            <button class="btn btn-sm btn-outline" data-toggle="${w.id}" data-status="${w.status}">${w.status==='active'?T('inactive'):T('active')}</button>
            <button class="btn btn-sm btn-outline" data-reset="${w.id}" title="${T('reset_password')}">${App.icon('key',16)}</button>
            <button class="btn btn-sm btn-outline" data-revoke="${w.id}" title="${T('revoke_sessions')}">${App.icon('logout',16)}</button>
          </div></td>
          </tr>`).join('') || emptyRow(7)}
      </tbody></table></div>`;
    c.querySelectorAll('[data-toggle]').forEach((b) => b.onclick = async () => {
      const ns = b.dataset.status === 'active' ? 'inactive' : 'active';
      await App.api(`/admin/wholesalers/${b.dataset.toggle}/status`, { method: 'POST', body: { status: ns } }); navigate('wholesalers');
    });
    c.querySelectorAll('[data-reset]').forEach((b) => b.onclick = async () => {
      const r = await App.api(`/admin/wholesalers/${b.dataset.reset}/reset-password`, { method: 'POST' });
      showTempPassword(r.tempPassword);
    });
    c.querySelectorAll('[data-revoke]').forEach((b) => b.onclick = async () => {
      await App.api(`/admin/wholesalers/${b.dataset.revoke}/revoke-sessions`, { method: 'POST' }); App.toast(T('save'), 'ok');
    });
    c.querySelector('#add-w').onclick = () => formModal(T('add_wholesaler'), [
      { name: 'name', label: T('name'), required: true },
      { name: 'location', label: T('location') },
      { name: 'contact', label: T('contact') },
      { name: 'username', label: T('username'), required: true },
      { name: 'password', label: T('password'), type: 'password', required: true },
    ], async (v) => { await App.api('/admin/wholesalers', { method: 'POST', body: v }); navigate('wholesalers'); });
  }

  /* ------------------------------ Reports ------------------------------ */
  async function secReports(c) {
    const r = await App.api('/admin/reports');
    const expBtn = (type) => `<button class="btn btn-sm btn-outline" data-export="${type}">${App.icon('download',16)} CSV</button>`;
    c.innerHTML = `
      <div class="chart-grid">
        <div class="card card-pad"><div class="flex items-center"><h3 style="font-size:.98rem;flex:1">${T('scans_by_date')}</h3>${expBtn('scans')}</div><div class="chart-box"><canvas id="r-scans"></canvas></div></div>
        <div class="card card-pad"><div class="flex items-center"><h3 style="font-size:.98rem;flex:1">${T('farmers_by_date')}</h3>${expBtn('farmers')}</div><div class="chart-box"><canvas id="r-regs"></canvas></div></div>
      </div>
      <div class="section-title"><h2>${T('most_scanned')}</h2><span class="spacer"></span>${expBtn('products')}</div>
      <div class="card card-pad">${miniBars(r.mostScannedProducts.map((p) => [p.name, p.scans]))}</div>
      <div class="section-title"><h2>${T('popular_rewards')}</h2><span class="spacer"></span>${expBtn('redemptions')}</div>
      <div class="card card-pad">${miniBars(r.popularRewards.map((p) => [p.name, p.redemptions]))}</div>
      <div class="chart-grid" style="margin-top:1.4rem">
        <div class="card"><div class="card-head"><h3>${T('redeems_per_wholesaler')}</h3></div><div class="card-pad">${miniBars(r.redemptionsPerWholesaler.map((w) => [w.name, w.redemptions]))}</div></div>
        <div class="card"><div class="card-head"><h3>${T('batch_performance')}</h3></div><div class="table-wrap"><table class="data"><thead><tr>
          <th>${T('batch_number')}</th><th>${T('product_name')}</th><th>${T('generated')}</th><th>${T('used')}</th></tr></thead><tbody>
          ${r.batchPerformance.map((b) => `<tr><td class="mono">${App.esc(b.batch_number)}</td><td>${App.esc(b.product)}</td>
            <td>${App.num(b.generated)}</td><td><b>${App.num(b.used)}</b></td></tr>`).join('') || emptyRow(4)}</tbody></table></div></div>
      </div>
      <div class="section-title"><h2>${T('suspicious_activity')}</h2></div>
      <div class="card card-pad">${r.suspicious.map((s) => `<div class="logline">
        ${App.badgeStatus(s.severity)}<div style="flex:1"><b>${App.esc(s.action)}</b> <span class="code">${App.esc(s.detail||'')}</span></div>
        <span class="muted">${App.date(s.created_at)}</span></div>`).join('') || `<p class="muted">${T('none_found')}</p>`}</div>`;

    charts.rscans = barChart('r-scans', r.scansByDate.slice(0, 14).reverse().map((d) => d.d.slice(5)), r.scansByDate.slice(0, 14).reverse().map((d) => d.c), '#22a65c');
    charts.rregs = barChart('r-regs', r.registrationsByDate.slice(0, 14).reverse().map((d) => d.d.slice(5)), r.registrationsByDate.slice(0, 14).reverse().map((d) => d.c), '#00a6c4');
    c.querySelectorAll('[data-export]').forEach((b) => b.onclick = () => window.location = `/api/admin/reports/export?type=${b.dataset.export}`);
  }

  /* ------------------------------ Audit ------------------------------ */
  async function secAudit(c) {
    const render = async (offset = 0) => {
      const { logs, total, limit } = await App.api(`/admin/audit?limit=30&offset=${offset}`);
      c.innerHTML = `<div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('date')}</th><th>${T('severity')}</th><th>${T('action')}</th><th>${T('details')}</th><th>IP</th></tr></thead><tbody>
        ${logs.map((l) => `<tr><td class="muted">${App.date(l.created_at)}</td><td>${App.badgeStatus(l.severity)}</td>
          <td><b>${App.esc(l.action)}</b><br><small class="muted">${App.esc(l.actor_role||'')} ${l.actor_id||''}</small></td>
          <td class="code" style="font-size:.8rem;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${App.esc(l.detail||'')}</td>
          <td class="mono muted">${App.esc(l.ip||'')}</td></tr>`).join('') || emptyRow(5)}
      </tbody></table></div><div id="au-pager"></div>`;
      c.querySelector('#au-pager').appendChild(App.pager(total, limit, offset, render));
    };
    await render(0);
  }

  /* ------------------------------ Redemptions ------------------------------ */
  async function secRedemptions(c) {
    const canCancel = can('redemptions.cancel');
    const state = { status: '', q: '', offset: 0 };
    const render = async () => {
      const qs = `?limit=25&offset=${state.offset}` + (state.status ? `&status=${state.status}` : '') + (state.q ? `&q=${encodeURIComponent(state.q)}` : '');
      const { redemptions, total, limit } = await App.api('/admin/redemptions' + qs);
      body.innerHTML = `<div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('redemption_code')}</th><th>${T('farmer')}</th><th>${T('reward')}</th><th>${T('points')}</th>
        <th>${T('wholesalers')}</th><th>${T('status')}</th><th>${T('date')}</th>${canCancel?`<th>${T('actions')}</th>`:''}</tr></thead><tbody>
        ${redemptions.map((r) => `<tr>
          <td class="mono"><b>${App.esc(r.code)}</b></td>
          <td>${App.esc(r.farmer_name)}<br><small class="muted mono">${App.esc(r.farmer_mobile)}</small></td>
          <td>${App.esc(r.reward_name)}</td><td class="mono">${App.num(r.points_spent)}</td>
          <td>${App.esc(r.wholesaler_name||'—')}</td><td>${App.badgeStatus(r.status)}</td><td class="muted">${App.date(r.created_at)}</td>
          ${canCancel?`<td>${(r.status==='pending'||r.status==='expired')?`<button class="btn btn-sm btn-outline" data-cancel="${r.id}">${T('cancel_redemption')}</button>`:'—'}</td>`:''}
        </tr>`).join('') || emptyRow(canCancel?8:7)}
      </tbody></table></div><div id="rd-pager"></div>`;
      body.querySelector('#rd-pager').appendChild(App.pager(total, limit, state.offset, (o) => { state.offset = o; render(); }));
      body.querySelectorAll('[data-cancel]').forEach((b) => b.onclick = async () => {
        if (!await App.confirm(T('cancel_redemption'), T('confirm') + '?')) return;
        await App.api(`/admin/redemptions/${b.dataset.cancel}/cancel`, { method: 'POST', body: { reason: 'admin_cancel' } });
        App.toast(T('save'), 'ok'); render();
      });
    };
    c.innerHTML = `<div class="toolbar">
      <div class="search-box">${App.icon('search',18)}<input class="input" id="rd-search" placeholder="${T('search')}…"></div>
      <select class="select" id="rd-status" style="max-width:180px">
        <option value="">${T('all')}</option><option value="pending">${T('pending')}</option>
        <option value="redeemed">${T('completed')}</option><option value="expired">${T('expired')}</option><option value="cancelled">${T('cancelled')}</option>
      </select></div><div id="rd-body"></div>`;
    const body = c.querySelector('#rd-body');
    let tmr; c.querySelector('#rd-search').oninput = (e) => { clearTimeout(tmr); tmr = setTimeout(() => { state.q = e.target.value.trim(); state.offset = 0; render(); }, 250); };
    c.querySelector('#rd-status').onchange = (e) => { state.status = e.target.value; state.offset = 0; render(); };
    await render();
  }

  /* ------------------------------ Users (staff) ------------------------------ */
  async function secUsers(c) {
    const { users, roles } = await App.api('/admin/users');
    c.innerHTML = `<div class="toolbar"><span class="spacer"></span>
      <button class="btn btn-primary" id="add-user">${App.icon('plus')} ${T('add_user')}</button></div>
      <div class="table-wrap card"><table class="data"><thead><tr>
        <th>${T('username')}</th><th>${T('name')}</th><th>${T('role')}</th><th>2FA</th><th>${T('sessions')}</th>
        <th>${T('last_login')}</th><th>${T('status')}</th><th>${T('actions')}</th></tr></thead><tbody>
        ${users.map((u) => `<tr>
          <td class="mono"><b>${App.esc(u.username)}</b></td><td>${App.esc(u.name)}</td>
          <td><select class="select" data-role="${u.id}" style="min-width:150px">${roles.map((r) => `<option value="${r}" ${r===u.role?'selected':''}>${r}</option>`).join('')}</select></td>
          <td>${u.mfa_enabled?App.badgeStatus('active'):'<span class="badge badge-muted">—</span>'}</td>
          <td class="mono">${App.num(u.active_sessions)}</td>
          <td class="muted">${u.last_login_at?App.date(u.last_login_at):'—'}</td>
          <td>${App.badgeStatus(u.status==='active'?'active':(u.status==='archived'?'archived':'disabled'))}</td>
          <td><div class="flex gap-sm wrap">
            <select class="select btn-sm" data-status="${u.id}" style="min-width:110px">
              ${['active','disabled','archived'].map((s) => `<option value="${s}" ${s===u.status?'selected':''}>${T(s==='active'?'active':(s==='archived'?'archived':'inactive'))}</option>`).join('')}</select>
            <button class="btn btn-sm btn-outline" data-reset="${u.id}" title="${T('reset_password')}">${App.icon('key',16)}</button>
            <button class="btn btn-sm btn-outline" data-revoke="${u.id}" title="${T('revoke_sessions')}">${App.icon('logout',16)}</button>
          </div></td></tr>`).join('') || emptyRow(8)}
      </tbody></table></div>
      <p class="muted" style="margin-top:.8rem;font-size:.82rem">🔒 ${T('security')}: ${T('temp_password_notice')}</p>`;
    c.querySelectorAll('[data-role]').forEach((s) => s.onchange = async () => {
      try { await App.api(`/admin/users/${s.dataset.role}/role`, { method: 'POST', body: { role: s.value } }); App.toast(T('save'), 'ok'); }
      catch (e) { App.toast(e.data && e.data.error === 'last_super_admin' ? 'Protected: last SUPER_ADMIN' : T('something_wrong'), 'err'); navigate('users'); }
    });
    c.querySelectorAll('[data-status]').forEach((s) => s.onchange = async () => {
      try { await App.api(`/admin/users/${s.dataset.status}/status`, { method: 'POST', body: { status: s.value } }); App.toast(T('save'), 'ok'); }
      catch (e) { App.toast(e.data && e.data.error === 'last_super_admin' ? 'Protected: last SUPER_ADMIN' : T('something_wrong'), 'err'); navigate('users'); }
    });
    c.querySelectorAll('[data-reset]').forEach((b) => b.onclick = async () => {
      const r = await App.api(`/admin/users/${b.dataset.reset}/reset-password`, { method: 'POST' }); showTempPassword(r.tempPassword);
    });
    c.querySelectorAll('[data-revoke]').forEach((b) => b.onclick = async () => {
      await App.api(`/admin/users/${b.dataset.revoke}/revoke-sessions`, { method: 'POST' }); App.toast(T('save'), 'ok');
    });
    c.querySelector('#add-user').onclick = () => formModal(T('create_user'), [
      { name: 'username', label: T('username'), required: true },
      { name: 'name', label: T('name'), required: true },
      { name: 'role', label: T('role'), type: 'select', required: true, options: roles.map((r) => [r, r]) },
    ], async (v) => { const r = await App.api('/admin/users', { method: 'POST', body: v }); navigate('users'); showTempPassword(r.tempPassword, r.username); });
  }

  function showTempPassword(pw, username) {
    App.modal({ title: T('reset_password'),
      body: `<p class="muted">${T('temp_password_is')}</p>
        ${username?`<p class="mono">${T('username')}: <b>${App.esc(username)}</b></p>`:''}
        <div class="flex items-center gap" style="background:var(--line-2);padding:.9rem 1rem;border-radius:12px;margin-top:.5rem">
          <b class="mono" id="tp-val" style="font-size:1.2rem;letter-spacing:.05em;flex:1">${App.esc(pw)}</b>
          <button class="btn btn-sm btn-outline" id="tp-copy">${T('copy')}</button></div>
        <p class="hint" style="margin-top:.6rem">${T('temp_password_notice')}</p>`,
      footer: `<button class="btn btn-primary" data-close>${T('close')}</button>`,
      onOpen: (el) => { el.querySelector('#tp-copy').onclick = () => { navigator.clipboard && navigator.clipboard.writeText(pw); App.toast(T('copied'), 'ok'); }; } });
  }

  /* ------------------------------ Settings ------------------------------ */
  async function secSettings(c) {
    const { settings: s } = await App.api('/admin/settings');
    const rb = s['fraud.risk_bands'] || { medium: 30, high: 70 };
    c.innerHTML = `
      <div class="section-title"><h2>${T('account_security')}</h2></div>
      <div class="card card-pad" style="display:flex;gap:.6rem;flex-wrap:wrap">
        <button class="btn btn-outline" id="set-change-pw">${App.icon('key')} ${T('change_password')}</button>
        <button class="btn btn-outline" id="set-mfa">${App.icon('shield')} ${T('enable_mfa')}</button>
        <button class="btn btn-outline" id="set-logout-all">${App.icon('logout')} ${T('logout_all')}</button>
      </div>
      <div class="section-title"><h2>${T('fraud_thresholds')}</h2></div>
      <div class="card card-pad">
        <div class="row">
          <div class="field"><label>Medium risk score</label><input class="input" id="rb-medium" type="number" value="${rb.medium}"></div>
          <div class="field"><label>High risk score</label><input class="input" id="rb-high" type="number" value="${rb.high}"></div>
        </div>
        <button class="btn btn-primary" id="save-bands">${T('save')}</button>
        <p class="hint" style="margin-top:.6rem">Transactions scoring ≥ high are held for manual review in Fraud Alerts.</p>
      </div>`;
    c.querySelector('#set-change-pw').onclick = () => App.changePasswordModal({});
    c.querySelector('#set-logout-all').onclick = async () => {
      if (!await App.confirm(T('logout_all'), T('confirm') + '?')) return;
      await App.api('/auth/logout-all', { method: 'POST' }); App.resetCsrf(); user = null; renderLogin();
    };
    c.querySelector('#set-mfa').onclick = () => setupMfa();
    c.querySelector('#save-bands').onclick = (e) => App.busy(e.target, async () => {
      const medium = parseInt(c.querySelector('#rb-medium').value, 10), high = parseInt(c.querySelector('#rb-high').value, 10);
      await App.api('/admin/settings', { method: 'PUT', body: { key: 'fraud.risk_bands', value: { medium, high } } });
      App.toast(T('save') + ' ✓', 'ok');
    }, 'saving');
  }

  async function setupMfa() {
    const { secret, otpauth } = await App.api('/admin/mfa/setup', { method: 'POST' });
    App.modal({ title: T('enable_mfa'),
      body: `<p class="muted">${T('scan_your_2fa')}</p>
        <div class="card card-pad mono" style="word-break:break-all;font-size:.8rem">${App.esc(otpauth)}</div>
        <div class="field" style="margin-top:1rem"><label>${T('mfa_code')}</label><input class="input mono" id="mfa-code" inputmode="numeric" maxlength="6" placeholder="000000"></div>`,
      footer: `<button class="btn btn-outline" data-close>${T('cancel')}</button><button class="btn btn-primary" id="mfa-go">${T('enable_mfa')}</button>`,
      onOpen: (el, close) => { el.querySelector('#mfa-go').onclick = (e) => App.busy(e.target, async () => {
        try { await App.api('/admin/mfa/enable', { method: 'POST', body: { code: el.querySelector('#mfa-code').value.trim() } }); App.toast(T('save') + ' ✓', 'ok'); close(); }
        catch (err) { App.toast(T('otp_invalid'), 'err'); }
      }); } });
  }

  /* ------------------------------ Form modal ------------------------------ */
  function formModal(title, fields, onSubmit, hint) {
    const body = (hint ? `<p class="muted" style="margin:0 0 1rem">${App.esc(hint)}</p>` : '') + fields.map((f) => {
      if (f.type === 'select') return `<div class="field"><label>${f.label}</label><select class="select" name="${f.name}">
        <option value="">${T('select')}…</option>${f.options.map(([v, l]) => `<option value="${v}">${App.esc(l)}</option>`).join('')}</select></div>`;
      if (f.type === 'textarea') return `<div class="field"><label>${f.label}</label><textarea class="input" name="${f.name}" rows="3"></textarea></div>`;
      return `<div class="field"><label>${f.label}</label><input class="input" name="${f.name}" type="${f.type||'text'}" placeholder="${f.placeholder||''}"></div>`;
    }).join('');
    App.modal({ title, body,
      footer: `<button class="btn btn-outline" data-close>${T('cancel')}</button><button class="btn btn-primary" data-save>${T('save')}</button>`,
      onOpen: (el, close) => {
        el.querySelector('[data-save]').onclick = async (e) => {
          const v = {}; let ok = true;
          fields.forEach((f) => { const inp = el.querySelector(`[name="${f.name}"]`); v[f.name] = inp.value.trim();
            if (f.required && !v[f.name]) { inp.style.borderColor = 'var(--danger)'; ok = false; } });
          if (!ok) return App.toast(T('none_found'), 'warn');
          e.target.disabled = true;
          try { await onSubmit(v); close(); App.toast(T('save') + ' ✓', 'ok'); }
          catch (err) { App.toast(App.esc((err.data && err.data.error) || 'error'), 'err'); e.target.disabled = false; }
        };
      } });
  }

  /* ------------------------------ Chart helpers ------------------------------ */
  function baseOpts() { return { responsive: true, maintainAspectRatio: false,
    plugins: { legend: { position: 'bottom', labels: { usePointStyle: true, boxWidth: 8, font: { family: 'inherit' } } } },
    scales: { y: { beginAtZero: true, grid: { color: '#eef2f0' }, ticks: { precision: 0 } }, x: { grid: { display: false } } } }; }
  function lineDs(label, data, color) { return { label, data, borderColor: color, backgroundColor: color + '22',
    fill: true, tension: .38, borderWidth: 2.5, pointRadius: 0, pointHoverRadius: 4 }; }
  function barChart(id, labels, data, color) { return new Chart(id, { type: 'bar',
    data: { labels, datasets: [{ data, backgroundColor: color, borderRadius: 6, maxBarThickness: 34 }] },
    options: { ...baseOpts(), plugins: { legend: { display: false } } } }); }
  function mergeDays(a, b) {
    const days = []; for (let i = 13; i >= 0; i--) { const d = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10); days.push(d); }
    const map = (arr) => Object.fromEntries(arr.map((x) => [x.d, x.c]));
    const ma = map(a), mb = map(b);
    return { labels: days.map((d) => d.slice(5)), scans: days.map((d) => ma[d] || 0), regs: days.map((d) => mb[d] || 0) };
  }
  function miniBars(pairs) {
    const max = Math.max(1, ...pairs.map((p) => p[1]));
    return `<div class="mini-list">${pairs.map(([l, v]) => `<div class="mini-row">
      <span class="lbl">${App.esc(l)}</span><span class="bar"><i style="width:${(v/max*100).toFixed(0)}%"></i></span>
      <span class="val mono">${App.num(v)}</span></div>`).join('') || `<p class="muted">${T('none_found')}</p>`}</div>`;
  }
  const emptyRow = (cols) => `<tr><td colspan="${cols}"><div class="empty" style="padding:2rem">${App.icon('inbox',40)}<p>${T('none_found')}</p></div></td></tr>`;
})();
