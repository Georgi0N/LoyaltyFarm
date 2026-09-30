'use strict';
/**
 * Build a printable QR sheet from a generated print file (data/exports/*.csv).
 *
 *   node scripts/print-qr.js --latest              # use the newest export CSV
 *   node scripts/print-qr.js data/exports/qr_X.csv # use a specific file
 *   node scripts/print-qr.js --latest --token      # encode the raw token instead of the URL
 *
 * Output: an .print.html next to the CSV. Open it in a browser and press Ctrl+P
 * (choose your label/sticker sheet size). Each QR encodes the scan_url so a normal
 * phone camera opens the farmer app with the code pre-filled.
 */
const fs = require('fs');
const path = require('path');
const QRCode = require('qrcode');

const EXPORT_DIR = path.join(__dirname, '..', 'data', 'exports');
const args = process.argv.slice(2);
const useToken = args.includes('--token');

function newestCsv() {
  if (!fs.existsSync(EXPORT_DIR)) return null;
  const files = fs.readdirSync(EXPORT_DIR).filter((f) => f.endsWith('.csv'))
    .map((f) => ({ f, t: fs.statSync(path.join(EXPORT_DIR, f)).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  return files.length ? path.join(EXPORT_DIR, files[0].f) : null;
}

const target = args.find((a) => a.endsWith('.csv'));
const csvPath = args.includes('--latest') || !target ? newestCsv() : path.resolve(target);
if (!csvPath || !fs.existsSync(csvPath)) {
  console.error('No print CSV found. Generate a batch in Admin → QR Codes → Generate first,\nthen run:  node scripts/print-qr.js --latest');
  process.exit(1);
}

// Minimal CSV parser (handles the simple quoted cells this app writes).
function parse(csv) {
  const lines = csv.replace(/^﻿/, '').trim().split(/\r?\n/);
  const cols = lines[0].split(',').map((c) => c.replace(/^"|"$/g, ''));
  return lines.slice(1).map((line) => {
    const cells = line.match(/("([^"]|"")*"|[^,]*)/g).filter((_, i, a) => i < a.length - 1 || a[i] !== '');
    const vals = line.split(',').map((c) => c.replace(/^"|"$/g, '').replace(/""/g, '"'));
    const row = {}; cols.forEach((c, i) => { row[c] = vals[i]; }); return row;
  });
}

(async () => {
  const rows = parse(fs.readFileSync(csvPath, 'utf8'));
  console.log(`Rendering ${rows.length} QR codes from ${path.basename(csvPath)} ...`);

  const cards = [];
  for (const r of rows) {
    const payload = useToken ? r.token : (r.scan_url || r.token);
    const dataUrl = await QRCode.toDataURL(payload, { margin: 1, width: 260, errorCorrectionLevel: 'M',
      color: { dark: '#0E7A43', light: '#ffffff' } });
    cards.push(`<div class="label">
      <img src="${dataUrl}" alt="QR">
      <div class="tok">${r.token}</div>
      <div class="meta">${r.points ? r.points + ' pts' : ''}${r.batch ? ' · ' + r.batch : ''}</div>
    </div>`);
  }

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Hasad QR labels</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: system-ui, Arial, sans-serif; margin: 12mm; color: #10241b; }
  .head { display:flex; align-items:center; gap:10px; margin-bottom:8mm; }
  .head b { font-size: 18px; }
  .sheet { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6mm; }
  .label { border: 1px dashed #cfe0d6; border-radius: 8px; padding: 6px; text-align: center; page-break-inside: avoid; }
  .label img { width: 100%; height: auto; }
  .tok { font-family: ui-monospace, monospace; font-size: 11px; font-weight: 700; letter-spacing: .04em; margin-top: 2px; word-break: break-all; }
  .meta { font-size: 10px; color: #6b7d75; }
  @media print { .head { display:none; } body { margin: 8mm; } @page { margin: 8mm; } }
</style></head>
<body>
  <div class="head"><b>Hasad — QR labels</b><span>${rows.length} codes · ${path.basename(csvPath)} · encodes ${useToken ? 'token' : 'scan URL'}</span>
    <button onclick="window.print()" style="margin-left:auto;padding:8px 14px;border:0;border-radius:8px;background:#22a65c;color:#fff;font-weight:700;cursor:pointer">Print</button></div>
  <div class="sheet">${cards.join('')}</div>
</body></html>`;

  const outPath = csvPath.replace(/\.csv$/, '') + '.print.html';
  fs.writeFileSync(outPath, html, 'utf8');
  console.log(`\nDone. Open this file and press Ctrl+P to print:\n  ${outPath}\n`);
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
