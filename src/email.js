'use strict';
/**
 * Pluggable email sender (used for staff password-reset links).
 *
 * If SMTP is configured (SMTP_HOST + SMTP_USER, with nodemailer installed) mail is
 * sent for real. Otherwise the message is logged to the server console so the flow
 * is fully testable in development without a mail provider — mirroring how OTP
 * delivery is structured. Wire any provider (SMTP, SendGrid, Resend, SES) by
 * setting the SMTP_* env vars; no code change required.
 */
const config = require('./config');

let transporter; // undefined = not initialised, false = unavailable
function getTransporter() {
  if (transporter !== undefined) return transporter;
  if (config.SMTP_HOST && config.SMTP_USER) {
    try {
      // Lazy require so the app runs even if nodemailer isn't installed yet.
      const nodemailer = require('nodemailer');
      transporter = nodemailer.createTransport({
        host: config.SMTP_HOST,
        port: config.SMTP_PORT,
        secure: config.SMTP_SECURE,
        auth: { user: config.SMTP_USER, pass: config.SMTP_PASS },
      });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn('[email] SMTP configured but nodemailer not installed — falling back to console. Run `npm i nodemailer`.');
      transporter = false;
    }
  } else {
    transporter = false;
  }
  return transporter;
}

/** @returns {Promise<{delivered:boolean}>} — never throws to the caller. */
async function sendMail({ to, subject, text, html }) {
  const t = getTransporter();
  if (!t) {
    // eslint-disable-next-line no-console
    console.log(`\n[email] (not delivered — no SMTP configured)\n  to: ${to}\n  subject: ${subject}\n  ${text}\n`);
    return { delivered: false };
  }
  try {
    await t.sendMail({ from: config.EMAIL_FROM, to, subject, text, html });
    return { delivered: true };
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error('[email] send failed:', e.message);
    return { delivered: false };
  }
}

module.exports = { sendMail };
