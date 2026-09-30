'use strict';
/**
 * Secure QR print/export engine (product QR batches only).
 *
 * Tokens are decrypted from `token_enc` ONLY here, and only ever reached through
 * authenticated + permissioned + audited admin routes. Nothing is written to a
 * public folder; PDFs/ZIPs/CSVs are streamed to the authorized admin and never
 * persisted to disk.
 */
const zlib = require('zlib');
const QRCode = require('qrcode');
const PDFDocument = require('pdfkit');
const { db } = require('./db');
const { decryptToken } = require('./crypto');

const getBatch = db.prepare(
  `SELECT b.*, s.sku_code, s.size_label, p.name AS product_name
   FROM batches b JOIN skus s ON s.id=b.sku_id JOIN products p ON p.id=s.product_id WHERE b.id=?`
);
const countCodes = db.prepare('SELECT COUNT(*) c FROM product_qr_codes WHERE batch_id=?');
const rangeCodes = db.prepare(
  `SELECT id, token_enc, point_value, status FROM product_qr_codes WHERE batch_id=? ORDER BY id ASC LIMIT ? OFFSET ?`
);

/** Validate a 1-based inclusive range against the batch size. Returns {from,to} or throws. */
function resolveRange(total, fromRaw, toRaw, max) {
  let from = parseInt(fromRaw, 10); let to = parseInt(toRaw, 10);
  if (!Number.isInteger(from)) from = 1;
  if (!Number.isInteger(to)) to = Math.min(total, from + 49);
  if (from < 1 || to < from || from > total) { const e = new Error('invalid_range'); e.code = 'invalid_range'; throw e; }
  if (to > total) to = total;
  if (to - from + 1 > max) { const e = new Error('range_too_large'); e.code = 'range_too_large'; throw e; }
  return { from, to };
}

/** Return decrypted labels for a batch range (1-based). */
function getLabels(batch, from, to, baseUrl) {
  const rows = rangeCodes.all(batch.id, to - from + 1, from - 1);
  return rows.map((r, i) => {
    const token = decryptToken(r.token_enc);
    return {
      seq: from + i,
      token,
      scan_url: token ? `${baseUrl}/c/${token}` : '(unrecoverable)',
      points: r.point_value,
      status: r.status,
      batch: batch.batch_number,
      product: batch.product_name,
      sku: batch.sku_code,
    };
  });
}

async function qrDataUrl(payload) {
  return QRCode.toDataURL(payload, { margin: 2, width: 320, errorCorrectionLevel: 'M',
    color: { dark: '#000000', light: '#ffffff' } }); // high-contrast, reliable
}
async function qrPngBuffer(payload) {
  return QRCode.toBuffer(payload, { margin: 2, width: 512, errorCorrectionLevel: 'M', type: 'png',
    color: { dark: '#000000', light: '#ffffff' } });
}

/* ------------------------------- CSV ------------------------------- */
function csvCell(v) { let s = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; }
function buildCsv(labels) {
  const cols = ['seq', 'token', 'scan_url', 'sku', 'batch', 'product', 'points', 'status'];
  const head = cols.join(',');
  const body = labels.map((l) => cols.map((c) => csvCell(l[c])).join(',')).join('\r\n');
  return '﻿' + head + '\r\n' + body;
}

/* ------------------------------- ZIP (store/deflate, dependency-free) ------------------------------- */
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c; }
  return t;
})();
function crc32(buf) { let c = 0 ^ -1; for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]) & 0xff]; return (c ^ -1) >>> 0; }

/** Build a ZIP (deflate) archive in memory from [{name, data(Buffer)}]. */
function buildZip(entries) {
  const chunks = []; const central = []; let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const comp = zlib.deflateRawSync(e.data);
    const crc = crc32(e.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8); local.writeUInt16LE(0, 10); local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(comp.length, 18); local.writeUInt32LE(e.data.length, 22);
    local.writeUInt16LE(name.length, 26); local.writeUInt16LE(0, 28);
    chunks.push(local, name, comp);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0, 8);
    cen.writeUInt16LE(8, 10); cen.writeUInt16LE(0, 12); cen.writeUInt16LE(0, 14);
    cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(comp.length, 20); cen.writeUInt32LE(e.data.length, 24);
    cen.writeUInt16LE(name.length, 28); cen.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cen, name]));
    offset += local.length + name.length + comp.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...chunks, centralBuf, end]);
}

async function buildZipOfLabels(labels, useToken) {
  const entries = [];
  for (const l of labels) {
    entries.push({ name: `qr_${String(l.seq).padStart(6, '0')}_${l.token || l.seq}.png`,
      data: await qrPngBuffer(useToken ? l.token : l.scan_url) });
  }
  entries.push({ name: 'labels.csv', data: Buffer.from(buildCsv(labels), 'utf8') });
  return buildZip(entries);
}

/* ------------------------------- PDF (pdfkit) ------------------------------- */
async function buildPdf(res, batch, labels, opts = {}) {
  const cols = Math.min(4, Math.max(1, parseInt(opts.cols, 10) || 3));
  const landscape = opts.orientation === 'landscape';
  const doc = new PDFDocument({ size: 'A4', layout: landscape ? 'landscape' : 'portrait', margin: 28 });
  doc.pipe(res);

  const pageW = doc.page.width - doc.page.margins.left - doc.page.margins.right;
  const gap = 10;
  const cellW = (pageW - gap * (cols - 1)) / cols;
  const qrSize = Math.min(cellW - 8, 150);
  const cellH = qrSize + 46;
  let x = doc.page.margins.left, y = doc.page.margins.top + 24, col = 0;

  doc.fontSize(13).fillColor('#0e7a43').text(`Hasad — ${batch.product_name} (${batch.sku_code}) · ${batch.batch_number}`, doc.page.margins.left, doc.page.margins.top);
  doc.moveTo(doc.page.margins.left, doc.page.margins.top + 18).lineTo(doc.page.width - doc.page.margins.right, doc.page.margins.top + 18).strokeColor('#e6ece8').stroke();

  for (const l of labels) {
    if (y + cellH > doc.page.height - doc.page.margins.bottom) { doc.addPage(); x = doc.page.margins.left; y = doc.page.margins.top; col = 0; }
    const png = await qrPngBuffer(opts.useToken ? l.token : l.scan_url);
    doc.image(png, x + (cellW - qrSize) / 2, y, { width: qrSize, height: qrSize });
    doc.fontSize(8).fillColor('#10241b').text(l.token || '', x, y + qrSize + 2, { width: cellW, align: 'center' });
    doc.fontSize(7).fillColor('#6b7d75').text(`${l.points} pts · Scan to earn points`, x, y + qrSize + 14, { width: cellW, align: 'center' });
    col++;
    if (col >= cols) { col = 0; x = doc.page.margins.left; y += cellH + gap; } else { x += cellW + gap; }
  }
  doc.end();
}

module.exports = { getBatch, countCodes, resolveRange, getLabels, qrDataUrl, buildCsv, buildZipOfLabels, buildPdf };
