'use strict';
/**
 * Central configuration + secret loading.
 *
 * Secrets come from environment variables (see .env.example). In development we
 * fall back to fixed dev values so the prototype runs out-of-the-box, but in
 * production ('NODE_ENV=production') the process REFUSES to start with default
 * secrets — a real deployment must supply strong, unique values.
 */
require('dotenv').config();

// APP_ENV is the canonical switch; NODE_ENV is honoured too for tooling compatibility.
const APP_ENV = process.env.APP_ENV || process.env.NODE_ENV || 'development';
const IS_PROD = APP_ENV === 'production';

const DEV_DEFAULTS = {
  SESSION_SECRET: 'dev-session-secret-not-for-production',
  QR_HMAC_SECRET: 'dev-qr-hmac-secret-not-for-production',
  OTP_HMAC_SECRET: 'dev-otp-hmac-secret-not-for-production',
  REDEMPTION_HMAC_SECRET: 'dev-redemption-hmac-secret-not-for-production',
  QR_ENC_SECRET: 'dev-qr-encryption-secret-not-for-production',
};

function secret(name) {
  const v = process.env[name];
  if (v && v.length >= 16) return v;
  if (IS_PROD) {
    // Fail closed: never run in production with a weak/default/missing secret.
    throw new Error(`FATAL: ${name} must be set to a strong value in production.`);
  }
  return DEV_DEFAULTS[name];
}

const config = {
  APP_ENV,
  IS_PROD,
  APP_URL: process.env.APP_URL || '',
  DATABASE_URL: process.env.DATABASE_URL || '', // reserved for a future Postgres driver
  PORT: parseInt(process.env.PORT, 10) || 3000,

  // Notification/OTP providers (delivery wired in src/otp.js for production).
  OTP_PROVIDER: process.env.OTP_PROVIDER || '',
  OTP_API_KEY: process.env.OTP_API_KEY || '',
  WHATSAPP_API_KEY: process.env.WHATSAPP_API_KEY || '',
  EMAIL_PROVIDER: process.env.EMAIL_PROVIDER || '',

  SESSION_SECRET: secret('SESSION_SECRET'),
  QR_HMAC_SECRET: secret('QR_HMAC_SECRET'),
  OTP_HMAC_SECRET: secret('OTP_HMAC_SECRET'),
  REDEMPTION_HMAC_SECRET: secret('REDEMPTION_HMAC_SECRET'),
  QR_ENC_SECRET: secret('QR_ENC_SECRET'), // AES key material for at-rest token encryption

  // Exports/prints larger than this require the admin to re-enter their password.
  QR_EXPORT_REAUTH_THRESHOLD: parseInt(process.env.QR_EXPORT_REAUTH_THRESHOLD, 10) || 5000,
  QR_EXPORT_MAX: parseInt(process.env.QR_EXPORT_MAX, 10) || 20000, // hard cap per request

  COOKIE_SECURE: process.env.COOKIE_SECURE === 'true' || IS_PROD,
  TRUST_PROXY: process.env.TRUST_PROXY || 1,

  // OTP delivery: 'console' (dev) logs to server stdout; 'sms' would call a real
  // provider (not bundled). We NEVER return the OTP in an API response in prod.
  OTP_DELIVERY: process.env.OTP_DELIVERY || (IS_PROD ? 'sms' : 'console'),
  // Expose OTP to the dev client ONLY when explicitly allowed and not in prod.
  OTP_DEV_ECHO: !IS_PROD && process.env.OTP_DEV_ECHO !== 'false',

  // Session lifetimes (ms)
  SESSION_IDLE_MS: 1000 * 60 * 30,            // 30 min inactivity
  SESSION_ABSOLUTE_MS: 1000 * 60 * 60 * 24 * 7, // 7 day hard cap
};

if (!IS_PROD) {
  // eslint-disable-next-line no-console
  console.log('[config] Running in DEVELOPMENT mode with fallback secrets. Do NOT use in production.');
}

module.exports = config;
