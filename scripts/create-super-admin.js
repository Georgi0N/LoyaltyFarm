'use strict';
/**
 * Securely create (or repair) the first SUPER_ADMIN account.
 *
 *   node scripts/create-super-admin.js
 *
 * Prompts for username + name + password (hidden). The password must meet the
 * staff policy and is stored hashed (scrypt). No default credentials are ever
 * shipped. Safe to run against production to bootstrap the first admin.
 */
const readline = require('readline');
const { Writable } = require('stream');
const { db } = require('../src/db');
const { hashPassword } = require('../src/crypto');
const { isStrongPassword } = require('../src/security');

// A writable that can suppress echo for password entry.
let muted = false;
const mutableOut = new Writable({
  write(chunk, enc, cb) { if (!muted) process.stdout.write(chunk, enc); cb(); },
});
const rl = readline.createInterface({ input: process.stdin, output: mutableOut, terminal: true });

const ask = (q, hidden = false) => new Promise((resolve) => {
  process.stdout.write(q);
  muted = hidden;
  rl.question('', (ans) => { if (hidden) process.stdout.write('\n'); muted = false; resolve(ans.trim()); });
});

(async () => {
  console.log('\n=== Create SUPER_ADMIN ===\n');
  const username = (await ask('Username: ')).toLowerCase();
  if (!/^[a-z0-9_.]{3,40}$/.test(username)) { console.error('Invalid username (3-40 chars: a-z 0-9 _ .).'); process.exit(1); }

  const existing = db.prepare('SELECT id FROM admins WHERE username=?').get(username);
  const name = (await ask('Full name: ')) || 'Super Admin';

  const pw1 = await ask('Password (min 10, upper+lower+digit): ', true);
  if (!isStrongPassword(pw1)) { console.error('Weak password. Need >=10 chars with upper, lower and a digit.'); process.exit(1); }
  const pw2 = await ask('Confirm password: ', true);
  if (pw1 !== pw2) { console.error('Passwords do not match.'); process.exit(1); }

  const hash = hashPassword(pw1);
  if (existing) {
    db.prepare(`UPDATE admins SET name=?, password_hash=?, role='SUPER_ADMIN', status='active', must_change_password=0, failed_attempts=0, locked_until=NULL WHERE id=?`)
      .run(name, hash, existing.id);
    console.log(`\nUpdated existing account "${username}" as active SUPER_ADMIN.\n`);
  } else {
    db.prepare(`INSERT INTO admins (username, name, password_hash, role, status) VALUES (?,?,?, 'SUPER_ADMIN', 'active')`)
      .run(username, name, hash);
    console.log(`\nCreated SUPER_ADMIN "${username}".\n`);
  }
  rl.close();
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
