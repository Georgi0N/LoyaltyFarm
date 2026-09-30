'use strict';
/**
 * Central database layer (SQLite via better-sqlite3).
 *
 * Security-relevant design choices:
 *  - Foreign keys ON; strict UNIQUE constraints on identities and token hashes.
 *  - CHECK constraints so invalid states (negative stock, non-positive cost)
 *    cannot exist even if application code has a bug.
 *  - points_transactions and audit_logs are APPEND-ONLY, enforced by triggers
 *    that ABORT any UPDATE/DELETE — the ledger and audit trail are immutable.
 *  - Only token *hashes* are stored (see crypto.js), never raw QR secrets.
 *  - better-sqlite3 is synchronous + single-connection: transactions run to
 *    completion before the next request is processed, which (together with the
 *    conditional UPDATEs in services.js) makes double-spend races impossible.
 */
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const SCHEMA_VERSION = 4;
const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const TABLES = [
  'risk_reviews', 'idempotency_keys', 'sessions', 'otp_challenges', 'audit_logs',
  'points_transactions', 'redemptions', 'product_qr_codes', 'batches', 'skus',
  'products', 'rewards', 'farmers', 'wholesalers', 'admins', 'settings',
];

function dropAll() {
  db.pragma('foreign_keys = OFF');
  const tx = db.transaction(() => {
    for (const t of TABLES) db.exec(`DROP TABLE IF EXISTS ${t}`);
  });
  tx();
  db.pragma('foreign_keys = ON');
}

function createSchema() {
  db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'SUPER_ADMIN',
    status        TEXT NOT NULL DEFAULT 'active',
    mfa_enabled   INTEGER NOT NULL DEFAULT 0,
    totp_secret   TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS wholesalers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    location      TEXT,
    contact       TEXT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    last_login_at TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS farmers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    mobile         TEXT UNIQUE NOT NULL,            -- normalized canonical E.164-ish (07XXXXXXXXX)
    name           TEXT NOT NULL,
    language       TEXT NOT NULL DEFAULT 'ar',
    points_balance INTEGER NOT NULL DEFAULT 0 CHECK (points_balance >= 0),
    status         TEXT NOT NULL DEFAULT 'active',
    risk_state     TEXT NOT NULL DEFAULT 'low',
    created_ip     TEXT,
    last_ip        TEXT,
    last_login_at  TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS otp_challenges (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    phone        TEXT NOT NULL,
    code_hash    TEXT NOT NULL,                     -- HMAC(phone:code), never plaintext
    purpose      TEXT NOT NULL DEFAULT 'login',
    expires_at   TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    consumed     INTEGER NOT NULL DEFAULT 0,
    send_count   INTEGER NOT NULL DEFAULT 1,
    last_sent_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_ip   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_challenges(phone);

  CREATE TABLE IF NOT EXISTS sessions (
    sid        TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    user_id    INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    revoked    INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(role, user_id);

  CREATE TABLE IF NOT EXISTS idempotency_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scope      TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    actor_id   INTEGER NOT NULL,
    key        TEXT NOT NULL,
    response   TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (scope, actor_role, actor_id, key)
  );

  CREATE TABLE IF NOT EXISTS products (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    category   TEXT,
    status     TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS skus (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id     INTEGER NOT NULL REFERENCES products(id),
    sku_code       TEXT UNIQUE NOT NULL,
    size_label     TEXT,
    default_points INTEGER NOT NULL DEFAULT 0 CHECK (default_points >= 0),
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS batches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sku_id          INTEGER NOT NULL REFERENCES skus(id),
    batch_number    TEXT UNIQUE NOT NULL,
    production_date TEXT,
    expiry_date     TEXT,
    point_value     INTEGER NOT NULL DEFAULT 0 CHECK (point_value >= 0),
    status          TEXT NOT NULL DEFAULT 'active',
    qr_count        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS product_qr_codes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash   TEXT UNIQUE NOT NULL,              -- HMAC of the printed token (used for claim lookup)
    token_enc    TEXT,                              -- AES-256-GCM of the token (for authorized re-print/export only)
    batch_id     INTEGER NOT NULL REFERENCES batches(id),
    sku_id       INTEGER NOT NULL REFERENCES skus(id),
    product_id   INTEGER NOT NULL REFERENCES products(id),
    point_value  INTEGER NOT NULL CHECK (point_value >= 0),
    status       TEXT NOT NULL DEFAULT 'unused',    -- unused | used | blocked
    claimed_by   INTEGER REFERENCES farmers(id),
    claimed_at   TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_qr_batch ON product_qr_codes(batch_id);
  CREATE INDEX IF NOT EXISTS idx_qr_status ON product_qr_codes(status);

  CREATE TABLE IF NOT EXISTS rewards (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    name_ar        TEXT,
    description    TEXT,
    description_ar TEXT,
    image          TEXT,
    points_required INTEGER NOT NULL CHECK (points_required > 0),
    quantity       INTEGER NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS redemptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    code          TEXT UNIQUE NOT NULL,             -- human-typable RXXX-XXXX
    token         TEXT NOT NULL,                    -- farmer-scoped secret for QR rendering
    token_hash    TEXT UNIQUE NOT NULL,             -- HMAC used for wholesaler lookup
    farmer_id     INTEGER NOT NULL REFERENCES farmers(id),
    reward_id     INTEGER NOT NULL REFERENCES rewards(id),
    points_spent  INTEGER NOT NULL CHECK (points_spent > 0),
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | redeemed | expired | cancelled
    wholesaler_id INTEGER REFERENCES wholesalers(id),
    expires_at    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at  TEXT,
    cancel_reason TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_redemption_farmer ON redemptions(farmer_id);

  CREATE TABLE IF NOT EXISTS points_transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    farmer_id     INTEGER NOT NULL REFERENCES farmers(id),
    type          TEXT NOT NULL,                    -- earn | redeem | refund | adjust
    source        TEXT NOT NULL DEFAULT 'PRODUCT_PURCHASE',
    points        INTEGER NOT NULL,
    prev_balance  INTEGER,
    balance_after INTEGER NOT NULL CHECK (balance_after >= 0),
    qr_id         INTEGER REFERENCES product_qr_codes(id),
    redemption_id INTEGER REFERENCES redemptions(id),
    reference     TEXT,
    description   TEXT,
    created_by_role TEXT NOT NULL DEFAULT 'system',
    created_by_id INTEGER,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_txn_farmer ON points_transactions(farmer_id);
  -- Append-only ledger: block any mutation of history.
  CREATE TRIGGER IF NOT EXISTS trg_pt_no_update BEFORE UPDATE ON points_transactions
    BEGIN SELECT RAISE(ABORT, 'points_transactions is append-only'); END;
  CREATE TRIGGER IF NOT EXISTS trg_pt_no_delete BEFORE DELETE ON points_transactions
    BEGIN SELECT RAISE(ABORT, 'points_transactions is append-only'); END;

  CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id  TEXT,
    actor_role  TEXT,
    actor_id    INTEGER,
    action      TEXT NOT NULL,
    entity      TEXT,
    target_id   INTEGER,
    detail      TEXT,
    severity    TEXT NOT NULL DEFAULT 'info',       -- info | warning | alert
    result      TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
  CREATE TRIGGER IF NOT EXISTS trg_audit_no_update BEFORE UPDATE ON audit_logs
    BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
  CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete BEFORE DELETE ON audit_logs
    BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;

  CREATE TABLE IF NOT EXISTS risk_reviews (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    farmer_id   INTEGER REFERENCES farmers(id),
    kind        TEXT NOT NULL,                      -- claim | redeem | registration
    risk_score  INTEGER NOT NULL,
    reasons     TEXT,
    payload     TEXT,
    status      TEXT NOT NULL DEFAULT 'open',       -- open | approved | rejected
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_by INTEGER,
    resolved_at TEXT
  );

  CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  `);
}

// Version-gated (re)build. If the on-disk schema is stale, drop & recreate.
(function migrate() {
  const current = db.pragma('user_version', { simple: true });
  if (current !== SCHEMA_VERSION) {
    dropAll();
    createSchema();
    db.pragma(`user_version = ${SCHEMA_VERSION}`);
  } else {
    createSchema();
  }
})();

/** Force a clean rebuild (used by `npm run reset`). */
function rebuild() {
  dropAll();
  createSchema();
  db.pragma(`user_version = ${SCHEMA_VERSION}`);
}

/** Append an audit entry. Never throws (logging must not break request flows). */
function audit(e = {}) {
  try {
    db.prepare(
      `INSERT INTO audit_logs (request_id, actor_role, actor_id, action, entity, target_id, detail, severity, result, ip)
       VALUES (@request_id,@role,@id,@action,@entity,@target,@detail,@severity,@result,@ip)`
    ).run({
      request_id: e.requestId || null,
      role: e.role || null,
      id: e.id != null ? e.id : null,
      action: e.action,
      entity: e.entity || null,
      target: e.target != null ? e.target : null,
      detail: e.detail ? JSON.stringify(e.detail) : null,
      severity: e.severity || 'info',
      result: e.result || null,
      ip: e.ip || null,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('audit failed:', err.message);
  }
}

module.exports = { db, audit, rebuild, SCHEMA_VERSION };
