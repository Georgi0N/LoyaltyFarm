'use strict';
/**
 * Server-side session tracking on top of express-session.
 *
 * express-session gives us signed httpOnly cookies; this table adds:
 *  - session-fixation defence (regenerate id on login),
 *  - server-side revocation ("log out all devices"),
 *  - idle + absolute timeout enforced on every request.
 */
const { db, audit } = require('./db');
const config = require('./config');

const insert = db.prepare(
  `INSERT INTO sessions (sid, role, user_id, ip, user_agent) VALUES (?,?,?,?,?)
   ON CONFLICT(sid) DO UPDATE SET role=excluded.role, user_id=excluded.user_id, ip=excluded.ip,
     user_agent=excluded.user_agent, last_seen=datetime('now'), revoked=0`
);
const getRow = db.prepare('SELECT * FROM sessions WHERE sid=?');
const touch = db.prepare(`UPDATE sessions SET last_seen=datetime('now') WHERE sid=?`);

/**
 * Establish an authenticated session. Regenerates the session id first so a
 * pre-auth (attacker-fixed) id can never become an authenticated one.
 */
function login(req, sessionUser) {
  // Preserve the CSRF secret across regeneration. The session *id* still rotates
  // (fixation defence); the double-submit CSRF token is not an auth credential,
  // so keeping it avoids forcing a token refetch after login.
  const csrf = req.session.csrf;
  return new Promise((resolve) => {
    req.session.regenerate((err) => {
      if (err) return resolve(false);
      req.session.user = sessionUser;
      if (csrf) req.session.csrf = csrf;
      insert.run(req.sessionID, sessionUser.role, sessionUser.id, req.ip || null,
        String(req.get('user-agent') || '').slice(0, 200));
      req.session.save(() => resolve(true));
    });
  });
}

function destroy(req) {
  const sid = req.sessionID;
  return new Promise((resolve) => {
    db.prepare(`UPDATE sessions SET revoked=1 WHERE sid=?`).run(sid);
    req.session.destroy(() => resolve(true));
  });
}

function revokeAll(role, userId) {
  db.prepare(`UPDATE sessions SET revoked=1 WHERE role=? AND user_id=?`).run(role, userId);
}

/** Revoke every session for a user except the given one (used after password change). */
function revokeAllExcept(role, userId, keepSid) {
  db.prepare(`UPDATE sessions SET revoked=1 WHERE role=? AND user_id=? AND sid<>?`).run(role, userId, keepSid);
}

/** Count currently-active (non-revoked, non-expired) sessions for a user. */
function activeCount(role, userId) {
  return db.prepare(
    `SELECT COUNT(*) c FROM sessions WHERE role=? AND user_id=? AND revoked=0`
  ).get(role, userId).c;
}

/** Per-request validity check: revoked? idle? too old? */
function validate(req, res, next) {
  if (!req.session || !req.session.user) return next();
  const row = getRow.get(req.sessionID);
  if (!row || row.revoked) { return req.session.destroy(() => res.status(401).json({ error: 'session_revoked' })); }

  const now = Date.now();
  const lastSeen = new Date(row.last_seen.replace(' ', 'T') + 'Z').getTime();
  const created = new Date(row.created_at.replace(' ', 'T') + 'Z').getTime();
  if (now - lastSeen > config.SESSION_IDLE_MS || now - created > config.SESSION_ABSOLUTE_MS) {
    db.prepare(`UPDATE sessions SET revoked=1 WHERE sid=?`).run(req.sessionID);
    audit({ role: req.session.user.role, id: req.session.user.id, action: 'session_expired', ip: req.ip });
    return req.session.destroy(() => res.status(401).json({ error: 'session_expired' }));
  }
  touch.run(req.sessionID);
  next();
}

module.exports = { login, destroy, revokeAll, revokeAllExcept, activeCount, validate };
