'use strict';
const { db } = require('../src/db');
console.log('\nSample farmer logins (mobile number is the identity):');
db.prepare(`SELECT name, mobile, points_balance FROM farmers WHERE points_balance > 400 ORDER BY points_balance DESC LIMIT 5`)
  .all().forEach((f) => console.log(`  ${f.mobile}  —  ${f.name}  (${f.points_balance} pts)`));
process.exit(0);
