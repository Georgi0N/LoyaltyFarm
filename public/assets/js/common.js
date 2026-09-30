/* Shared client utilities: API, i18n, toasts, modals, formatting, icons. */
(function () {
  'use strict';
  const App = window.App = {};

  /* ------------------------------- Language ------------------------------- */
  App.lang = localStorage.getItem('hasad_lang') || 'ar';
  App.t = (key, vars) => {
    let s = (window.I18N[App.lang] && window.I18N[App.lang][key]) || window.I18N.en[key] || key;
    if (vars) Object.keys(vars).forEach((k) => { s = s.replace(`{${k}}`, vars[k]); });
    return s;
  };
  App.setLang = (lang) => {
    App.lang = lang; localStorage.setItem('hasad_lang', lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    App.applyI18n();
    document.dispatchEvent(new CustomEvent('langchange'));
  };
  App.applyI18n = () => {
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = App.t(el.dataset.i18n); });
    document.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.placeholder = App.t(el.dataset.i18nPh); });
  };
  App.initLang = () => {
    document.documentElement.lang = App.lang;
    document.documentElement.dir = App.lang === 'ar' ? 'rtl' : 'ltr';
  };

  /* ------------------------------- Formatting ------------------------------- */
  App.num = (n) => new Intl.NumberFormat(App.lang === 'ar' ? 'ar-EG' : 'en-US').format(n || 0);
  App.date = (s) => {
    if (!s) return '—';
    const d = new Date(s.replace(' ', 'T') + (s.includes('Z') ? '' : 'Z'));
    return new Intl.DateTimeFormat(App.lang === 'ar' ? 'ar-EG' : 'en-GB',
      { year: 'numeric', month: 'short', day: 'numeric' }).format(d);
  };
  App.esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  /* ------------------------------- API layer ------------------------------- */
  let csrfToken = null;
  async function getCsrf(force) {
    if (csrfToken && !force) return csrfToken;
    const r = await fetch('/api/csrf', { credentials: 'same-origin' });
    csrfToken = (await r.json()).csrfToken;
    return csrfToken;
  }
  App.resetCsrf = () => { csrfToken = null; };

  async function doFetch(path, method, body, headers) {
    const opts = { method, credentials: 'same-origin', headers: { ...(headers || {}) } };
    if (method !== 'GET') {
      opts.headers['X-CSRF-Token'] = await getCsrf();
      if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    }
    return fetch('/api' + path, opts);
  }

  App.api = async (path, { method = 'GET', body, headers } = {}) => {
    let res = await doFetch(path, method, body, headers);
    // Session rotated (login/logout) can invalidate the cached CSRF token — refresh once.
    if (res.status === 403 && method !== 'GET') {
      let d = null; try { d = await res.clone().json(); } catch (e) {}
      if (d && d.error === 'invalid_csrf') { await getCsrf(true); res = await doFetch(path, method, body, headers); }
    }
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-json (e.g. csv) */ }
    if (!res.ok) { const err = new Error((data && data.error) || 'request_failed'); err.status = res.status; err.data = data; throw err; }
    return data;
  };

  /* ------------------------------- Toast ------------------------------- */
  App.toast = (msg, type = '') => {
    let host = document.getElementById('toasts');
    if (!host) { host = document.createElement('div'); host.id = 'toasts'; document.body.appendChild(host); }
    const el = document.createElement('div');
    el.className = 'toast ' + type; el.textContent = msg;
    host.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(-8px)'; el.style.transition = '.3s'; setTimeout(() => el.remove(), 300); }, 3200);
  };

  /* ------------------------------- Modal ------------------------------- */
  App.modal = ({ title, body, footer, onOpen, dismissible = true }) => {
    const back = document.createElement('div');
    back.className = 'modal-backdrop';
    back.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="${App.esc(title)}">
      <div class="modal-head"><h3>${App.esc(title)}</h3><span class="spacer"></span>
        ${dismissible ? `<button class="btn btn-ghost btn-icon" data-close aria-label="${App.t('close')}">${App.icon('x')}</button>` : ''}</div>
      <div class="modal-body">${body || ''}</div>
      ${footer ? `<div class="modal-foot">${footer}</div>` : ''}</div>`;
    document.body.appendChild(back);
    const close = () => back.remove();
    back.addEventListener('click', (e) => { if (dismissible && (e.target === back || e.target.closest('[data-close]'))) close(); });
    document.addEventListener('keydown', function esc(e) { if (e.key === 'Escape') { if (dismissible) close(); document.removeEventListener('keydown', esc); } });
    // Focus first field for accessibility.
    setTimeout(() => { const f = back.querySelector('input,select,textarea,button'); if (f) f.focus(); }, 30);
    if (onOpen) onOpen(back, close);
    return { el: back, close };
  };

  /* ------------------------------- Busy guard (prevents double-submit) ------------------------------- */
  App.busy = async (btn, fn, labelKey) => {
    if (!btn || btn.dataset.busy) return;
    btn.dataset.busy = '1'; btn.disabled = true;
    const orig = btn.innerHTML;
    btn.innerHTML = `<span class="spinner" aria-hidden="true"></span>${labelKey ? ' ' + App.t(labelKey) : ''}`;
    try { return await fn(); }
    finally { delete btn.dataset.busy; btn.disabled = false; btn.innerHTML = orig; }
  };

  /* ------------------------------- Change password (staff, reusable) ------------------------------- */
  App.changePasswordModal = ({ force = false } = {}) => new Promise((resolve) => {
    App.modal({
      title: App.t('change_password'), dismissible: !force,
      body: `${force ? `<p class="muted" style="margin:0 0 1rem">${App.t('temp_password_notice')}</p>` : ''}
        <div class="field"><label>${App.t('current_password')}</label><input class="input" type="password" id="cp-cur" autocomplete="current-password"></div>
        <div class="field"><label>${App.t('new_password')}</label><input class="input" type="password" id="cp-new" autocomplete="new-password"><div class="hint">${App.t('password_policy')}</div></div>
        <div class="field"><label>${App.t('confirm_password')}</label><input class="input" type="password" id="cp-conf" autocomplete="new-password"></div>`,
      footer: `${force ? '' : `<button class="btn btn-outline" data-close>${App.t('cancel')}</button>`}<button class="btn btn-primary" id="cp-save">${App.t('save')}</button>`,
      onOpen: (el, close) => {
        el.querySelector('#cp-save').onclick = (e) => App.busy(e.target, async () => {
          const cur = el.querySelector('#cp-cur').value, nw = el.querySelector('#cp-new').value, cf = el.querySelector('#cp-conf').value;
          if (nw !== cf) return App.toast(App.t('passwords_mismatch'), 'warn');
          try {
            await App.api('/auth/change-password', { method: 'POST', body: { current: cur, next: nw } });
            App.toast(App.t('password_changed'), 'ok'); close(); resolve(true);
          } catch (err) {
            const map = { invalid_current: 'wrong_current', weak_password: 'weak_password' };
            App.toast(App.t(map[err.data && err.data.error] || 'something_wrong'), 'err');
          }
        }, 'saving');
        const cancel = el.querySelector('[data-close]');
        if (cancel) cancel.onclick = () => { close(); resolve(false); };
      },
    });
  });

  /* ------------------------------- Pager ------------------------------- */
  App.pager = (total, limit, offset, onPage) => {
    if (total <= limit) return document.createComment('');
    const page = Math.floor(offset / limit) + 1, pages = Math.ceil(total / limit);
    const wrap = document.createElement('div');
    wrap.className = 'pager';
    wrap.innerHTML = `<button class="btn btn-sm btn-outline" ${offset <= 0 ? 'disabled' : ''} data-prev>${App.icon('chevron')} ${App.t('prev')}</button>
      <span class="muted">${App.t('page')} ${App.num(page)} / ${App.num(pages)} · ${App.num(total)}</span>
      <button class="btn btn-sm btn-outline" ${offset + limit >= total ? 'disabled' : ''} data-next>${App.t('next')} ${App.icon('chevron')}</button>`;
    wrap.querySelector('[data-prev]').onclick = () => onPage(Math.max(0, offset - limit));
    wrap.querySelector('[data-next]').onclick = () => onPage(offset + limit);
    return wrap;
  };

  App.confirm = (title, message) => new Promise((resolve) => {
    App.modal({
      title,
      body: `<p style="margin:.2rem 0 0;color:var(--ink-2)">${App.esc(message)}</p>`,
      footer: `<button class="btn btn-outline" data-no>${App.t('cancel')}</button>
               <button class="btn btn-primary" data-yes>${App.t('confirm')}</button>`,
      onOpen: (el, close) => {
        el.querySelector('[data-yes]').onclick = () => { close(); resolve(true); };
        el.querySelector('[data-no]').onclick = () => { close(); resolve(false); };
      },
    });
  });

  /* ------------------------------- Icons (inline SVG) ------------------------------- */
  const P = 'stroke="currentColor" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"';
  const ICONS = {
    x: `<path d="M18 6 6 18M6 6l12 12" ${P}/>`,
    scan: `<path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M20 17v2a1 1 0 0 1-1 1h-2M7 20H5a1 1 0 0 1-1-1v-2M4 12h16" ${P}/>`,
    gift: `<path d="M20 12v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8M2 7h20v5H2zM12 21V7M12 7S11 3 8.5 3 5 5.5 7 7M12 7s1-4 3.5-4S19 5.5 17 7" ${P}/>`,
    history: `<path d="M3 12a9 9 0 1 0 9-9 9 9 0 0 0-7.5 4M3 4v4h4M12 8v4l3 2" ${P}/>`,
    user: `<path d="M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4 21a8 8 0 0 1 16 0" ${P}/>`,
    users: `<path d="M16 11a4 4 0 1 0-8 0M2 21a6 6 0 0 1 12 0M17 21a5 5 0 0 0-3-4.58M15 3a4 4 0 0 1 0 8" ${P}/>`,
    home: `<path d="M3 11l9-8 9 8M5 10v10h14V10" ${P}/>`,
    box: `<path d="M21 8l-9-5-9 5 9 5 9-5ZM3 8v8l9 5 9-5V8M12 13v8" ${P}/>`,
    layers: `<path d="M12 3 3 8l9 5 9-5-9-5ZM3 13l9 5 9-5M3 17l9 5 9-5" ${P}/>`,
    qr: `<path d="M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h2v2h-2zM18 14h2v2h-2zM14 18h2v2h-2zM18 18h2v2h-2z" ${P}/>`,
    award: `<path d="M12 15a6 6 0 1 0 0-12 6 6 0 0 0 0 12ZM8.2 13.5 7 22l5-3 5 3-1.2-8.5" ${P}/>`,
    store: `<path d="M3 9l1-5h16l1 5M4 9v11h16V9M4 9a2.5 2.5 0 0 0 5 0 2.5 2.5 0 0 0 5 0 2.5 2.5 0 0 0 5 0" ${P}/>`,
    chart: `<path d="M3 3v18h18M8 14v4M13 10v8M18 6v12" ${P}/>`,
    shield: `<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3Z" ${P}/>`,
    coins: `<path d="M12 8c4 0 7-1.3 7-3s-3-3-7-3-7 1.3-7 3 3 3 7 3ZM5 5v6c0 1.7 3 3 7 3s7-1.3 7-3V5M5 11v6c0 1.7 3 3 7 3s7-1.3 7-3v-6" ${P}/>`,
    check: `<path d="M20 6 9 17l-5-5" ${P}/>`,
    alert: `<path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" ${P}/>`,
    logout: `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" ${P}/>`,
    plus: `<path d="M12 5v14M5 12h14" ${P}/>`,
    search: `<path d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16ZM21 21l-4.3-4.3" ${P}/>`,
    download: `<path d="M12 3v12M7 10l5 5 5-5M5 21h14" ${P}/>`,
    leaf: `<path d="M11 20A7 7 0 0 1 4 13c0-4 3-9 11-10 1 8-2 14-7 15M4 21c1-4 4-7 8-9" ${P}/>`,
    chevron: `<path d="M9 6l6 6-6 6" ${P}/>`,
    camera: `<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2Z M12 17a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z" ${P}/>`,
    inbox: `<path d="M22 12h-6l-2 3h-4l-2-3H2M5 5h14l3 7v6a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-6Z" ${P}/>`,
    cog: `<path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-2.82 1.17V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 7 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 2.6 14H2.5a2 2 0 0 1 0-4H2.6A1.65 1.65 0 0 0 4.6 8.4L4.54 8.34A2 2 0 1 1 7.37 5.51l.06.06A1.65 1.65 0 0 0 9.25 5.9 1.65 1.65 0 0 0 10.42 4.38V4.3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 2.82 1.17l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 22 12h.09" ${P}/>`,
    key: `<path d="M15 7a4 4 0 1 1-4 4l-6 6H2v-3l6-6a4 4 0 0 1 7-1Z" ${P}/>`,
  };
  App.icon = (name, size = 20) => `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true">${ICONS[name] || ''}</svg>`;

  App.badgeStatus = (status) => {
    const map = { active: 'badge-ok', used: 'badge-muted', unused: 'badge-info', blocked: 'badge-danger',
      inactive: 'badge-muted', pending: 'badge-warn', completed: 'badge-ok', warning: 'badge-warn', alert: 'badge-danger' };
    return `<span class="badge ${map[status] || ''}"><span class="dot"></span>${App.t(status) !== status ? App.t(status) : status}</span>`;
  };

  App.initLang();
})();
