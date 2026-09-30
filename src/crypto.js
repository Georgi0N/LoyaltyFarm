'use strict';
/**
 * All cryptographic primitives in one audited place.
 *  - Password hashing: scrypt (memory-hard KDF, built into Node, no native build).
 *    NOTE: Argon2id is the recommended production upgrade — see SECURITY.md.
 *  - Secure random tokens (>=128 bits entropy) for QR + redemption codes.
 *  - Keyed HMAC-SHA256 hashing so we store token *hashes*, not raw tokens.
 *  - Constant-time comparison + TOTP (RFC 6238) for admin MFA.
 */
const crypto = require('crypto');
const config = require('./config');

/* ------------------------------- Passwords (scrypt) ------------------------------- */
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const dk = crypto.scryptSync(String(password), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${dk.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    if (typeof stored !== 'string') return false;
    const [scheme, N, r, p, saltB64, hashB64] = stored.split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const dk = crypto.scryptSync(String(password), salt, expected.length,
      { N: +N, r: +r, p: +p, maxmem: 128 * (+N) * (+r) * 2 });
    return dk.length === expected.length && crypto.timingSafeEqual(dk, expected);
  } catch { return false; }
}

/* ------------------------------- Secure tokens ------------------------------- */
// Unambiguous alphabet (no 0/O/1/I/L/U) for human-readable printed codes.
const ALPHABET = 'ABCDEFGHJKMNPQRSTVWXYZ23456789'; // 30 symbols -> ~4.9 bits each

/** Product QR token: 26 symbols ≈ 128 bits of entropy. Non-sequential, unguessable. */
function qrToken() { return randomAlphabet(26); }

/** Redemption secret token embedded in the reward QR (≈160 bits). */
function redemptionToken() { return randomAlphabet(32); }

/** Human-typable redemption code for manual entry, grouped: RXXX-XXXX (≈49 bits). */
function redemptionCode() {
  const raw = randomAlphabet(8);
  return `R${raw.slice(0, 3)}-${raw.slice(3)}`;
}

function randomAlphabet(len) {
  let out = '';
  while (out.length < len) {
    const buf = crypto.randomBytes(len);
    for (let i = 0; i < buf.length && out.length < len; i++) {
      const v = buf[i];
      if (v < 240) out += ALPHABET[v % ALPHABET.length]; // reject bias tail (240..255)
    }
  }
  return out;
}

/* ------------------------------- At-rest encryption (AES-256-GCM) ------------------------------- */
// Used to store product QR tokens recoverably so an authorized admin can RE-PRINT
// or RE-EXPORT a batch later — while a DB-only leak (without QR_ENC_SECRET) reveals
// nothing usable. The key never leaves the server (env / secret manager).
const ENC_KEY = crypto.scryptSync(config.QR_ENC_SECRET, 'hasad-qr-enc-v1', 32);

function encryptToken(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64'); // iv(12)|tag(16)|ct
}

function decryptToken(stored) {
  try {
    const buf = Buffer.from(String(stored), 'base64');
    const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch { return null; }
}

/* ------------------------------- Keyed hashing ------------------------------- */
// Store HMAC of tokens so a DB leak does not expose usable physical QR codes.
const hmac = (value, key) =>
  crypto.createHmac('sha256', key).update(String(value)).digest('hex');

const hashQrToken = (token) => hmac(String(token).toUpperCase().trim(), config.QR_HMAC_SECRET);
const hashRedemptionToken = (token) => hmac(String(token).toUpperCase().trim(), config.REDEMPTION_HMAC_SECRET);
const hashOtp = (phone, code) => hmac(`${phone}:${code}`, config.OTP_HMAC_SECRET);

/* ------------------------------- Misc ------------------------------- */
const randomId = (bytes = 16) => crypto.randomBytes(bytes).toString('hex');

/** A strong temporary password that satisfies the staff policy (upper+lower+digit, 12 chars). */
function tempPassword() {
  const U = 'ABCDEFGHJKMNPQRSTVWXYZ', L = 'abcdefghijkmnpqrstvwxyz', D = '23456789';
  const all = U + L + D;
  const pick = (s) => s[crypto.randomInt(s.length)];
  let out = pick(U) + pick(L) + pick(D);
  while (out.length < 12) out += pick(all);
  // shuffle
  return out.split('').sort(() => crypto.randomInt(3) - 1).join('');
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/* ------------------------------- TOTP (admin MFA) ------------------------------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function generateTotpSecret() {
  const bytes = crypto.randomBytes(20);
  let bits = '', out = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32[parseInt(bits.substr(i, 5), 2)];
  return out;
}

function base32Decode(s) {
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase()) {
    const idx = B32.indexOf(c);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return Buffer.from(bytes);
}

function totpAt(secret, counter) {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = h[h.length - 1] & 0xf;
  const bin = ((h[offset] & 0x7f) << 24) | (h[offset + 1] << 16) | (h[offset + 2] << 8) | h[offset + 3];
  return String(bin % 1e6).padStart(6, '0');
}

/** Verify a TOTP code with a +/-1 step window for clock drift. */
function verifyTotp(secret, code, step = 30) {
  if (!secret || !/^\d{6}$/.test(String(code || ''))) return false;
  const counter = Math.floor(Date.now() / 1000 / step);
  for (let w = -1; w <= 1; w++) if (safeEqual(totpAt(secret, counter + w), code)) return true;
  return false;
}

function totpUri(secret, label, issuer = 'Hasad') {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&period=30&digits=6`;
}

module.exports = {
  hashPassword, verifyPassword,
  qrToken, redemptionToken, redemptionCode, randomAlphabet,
  hashQrToken, hashRedemptionToken, hashOtp, hmac,
  encryptToken, decryptToken,
  randomId, safeEqual, tempPassword,
  generateTotpSecret, verifyTotp, totpUri,
};
