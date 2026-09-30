'use strict';
/**
 * Idempotency for sensitive, retryable actions (claim, redeem).
 *
 * A client may pass an `Idempotency-Key` header; a retried request with the same
 * key returns the stored original response instead of executing twice. Because
 * better-sqlite3 is synchronous and single-connection, the first request fully
 * commits (including the key row) before any retry is processed — so even a
 * flaky-network double-tap cannot double-credit or double-redeem.
 */
const { db } = require('./db');

const find = db.prepare(
  `SELECT response FROM idempotency_keys WHERE scope=? AND actor_role=? AND actor_id=? AND key=?`
);
const store = db.prepare(
  `INSERT OR IGNORE INTO idempotency_keys (scope, actor_role, actor_id, key, response) VALUES (?,?,?,?,?)`
);

/**
 * @param key   client-supplied idempotency key (optional)
 * @param run   () => result  — the actual operation; only called once per key
 * @returns { replayed:boolean, result }
 */
function withIdempotency({ scope, role, id, key }, run) {
  if (!key) return { replayed: false, result: run() };
  const existing = find.get(scope, role, id, key);
  if (existing) return { replayed: true, result: JSON.parse(existing.response) };
  const result = run();
  try { store.run(scope, role, id, key, JSON.stringify(result)); } catch { /* ignore */ }
  return { replayed: false, result };
}

module.exports = { withIdempotency };
