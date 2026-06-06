const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const { q, asyncWrap } = require('../db/query');
const { optionalAuth } = require('../middleware/auth');
const { logEvent } = require('../utils/logger');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');

const MIME = {
  '.pdf': 'application/pdf',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.bmp': 'image/bmp', '.ico': 'image/x-icon', '.tiff': 'image/tiff',
  '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg', '.m4a': 'audio/mp4', '.flac': 'audio/flac',
  '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.avi': 'video/x-msvideo',
  '.mkv': 'video/x-matroska', '.webm': 'video/webm',
  '.doc': 'application/msword',
  '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel',
  '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.ppt': 'application/vnd.ms-powerpoint',
  '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  '.zip': 'application/zip', '.rar': 'application/vnd.rar',
  '.7z': 'application/x-7z-compressed', '.gz': 'application/gzip',
  '.tar': 'application/x-tar',
  '.txt': 'text/plain', '.csv': 'text/csv', '.json': 'application/json',
  '.xml': 'application/xml', '.md': 'text/markdown',
  '.js': 'application/javascript', '.css': 'text/css', '.html': 'text/html',
  '.exe': 'application/x-msdownload', '.dmg': 'application/x-apple-diskimage',
  '.deb': 'application/x-debian-package', '.apk': 'application/vnd.android.package-archive',
  '.iso': 'application/x-iso9660-image',
  '.epub': 'application/epub+zip',
  '.rtf': 'application/rtf',
};

const DOWNLOAD_BUCKET = new Map();
const DOWNLOAD_WINDOW_MS = 60_000;
const DOWNLOAD_MAX = 30;
function checkDownloadRate(ip) {
  const now = Date.now();
  const arr = (DOWNLOAD_BUCKET.get(ip) || []).filter(t => now - t < DOWNLOAD_WINDOW_MS);
  if (arr.length >= DOWNLOAD_MAX) return false;
  arr.push(now);
  DOWNLOAD_BUCKET.set(ip, arr);
  if (DOWNLOAD_BUCKET.size > 5000) {
    for (const [k, v] of DOWNLOAD_BUCKET) {
      if (!v.some(t => now - t < DOWNLOAD_WINDOW_MS)) DOWNLOAD_BUCKET.delete(k);
    }
  }
  return true;
}

const sanitizeFilename = (name) => {
  if (!name) return 'download';
  return String(name).replace(/[\x00-\x1f\x7f<>:"|?*\\\/]/g, '_').trim().substring(0, 200) || 'download';
};

const safeJoin = (rel) => {
  const clean = String(rel || '').replace(/\.\.+/g, '').replace(/[\\\/]/g, '');
  const full = path.join(uploadDir, clean);
  if (!full.startsWith(uploadDir + path.sep) && full !== uploadDir) return null;
  return full;
};

async function isOwnerOfQr(qrId, userId) {
  if (!qrId || !userId) return false;
  const row = await q.get('SELECT user_id FROM qr_codes WHERE id = ?', [qrId]);
  return row && String(row.user_id) === String(userId);
}

router.get('/files/:qrId', optionalAuth, asyncWrap(async (req, res) => {
  const qrId = String(req.params.qrId || '').toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(404).json({ error: 'Not found' });

  const qr = await q.get('SELECT id, user_id, verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });

  const owner = req.user && String(req.user.id) === String(qr.user_id);
  if (qr.verify_code_hash && !owner && !req.headers['x-verify-token']) {
    return res.status(403).json({ error: 'Verification required' });
  }
  if (qr.verify_code_hash && !owner) {
    const ok = await bcrypt.compare(String(req.headers['x-verify-token'] || ''), qr.verify_code_hash);
    if (!ok) return res.status(403).json({ error: 'Invalid verification code' });
  }

  const files = await q.all(
    'SELECT id, original_name, original_size, mime_type, created_at FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC',
    [qrId]
  );
  res.json({ files });
}));

router.get('/d/:fileId', optionalAuth, asyncWrap(async (req, res) => {
  const fileId = parseInt(req.params.fileId, 10);
  if (!fileId || fileId < 1) return res.status(404).render('public-error', { message: 'File not found', code: 404 });

  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  if (!checkDownloadRate(ip)) {
    logEvent('warn', 'rate_limit_download', { fileId, ip });
    return res.status(429).render('public-error', { message: 'Too many download requests. Please try again in a minute.', code: 429 });
  }

  const file = await q.get(
    'SELECT f.id, f.qr_id, f.file_path, f.original_name, f.mime_type, f.original_size, q.verify_code_hash, q.is_active, q.user_id, q.expires_at, q.scan_limit, q.scan_count FROM file_uploads f JOIN qr_codes q ON f.qr_id = q.id WHERE f.id = ?',
    [fileId]
  );
  if (!file) return res.status(404).render('public-error', { message: 'File not found', code: 404 });
  if (!file.is_active) return res.render('public-expired', { reason: 'This QR code has been deactivated.' });
  if (file.expires_at && new Date(file.expires_at) < new Date()) {
    return res.render('public-expired', { reason: 'This QR code has expired.' });
  }
  if (file.scan_limit && file.scan_count >= file.scan_limit) {
    return res.render('public-expired', { reason: 'This QR code has reached its scan limit.' });
  }

  const isOwner = req.user && String(req.user.id) === String(file.user_id);
  const code = (req.query.code || '').toString().substring(0, 200);
  if (file.verify_code_hash && !isOwner) {
    if (!code) {
      if (req.accepts('html') && !req.xhr) {
        return res.redirect(`/q/${file.qr_id}`);
      }
      return res.status(403).json({ error: 'Verification code required' });
    }
    const valid = await bcrypt.compare(code, file.verify_code_hash);
    if (!valid) return res.status(403).render('public-error', { message: 'Invalid verification code', code: 403 });
  }

  const filePath = safeJoin(file.file_path);
  if (!filePath || !fs.existsSync(filePath)) {
    logEvent('error', 'file_missing_on_disk', { fileId, path: file.file_path });
    return res.status(404).render('public-error', { message: 'File not found', code: 404 });
  }

  const stat = fs.statSync(filePath);
  const ext = path.extname(file.original_name || '').toLowerCase();
  const contentType = file.mime_type && file.mime_type !== 'application/octet-stream' ? file.mime_type : (MIME[ext] || 'application/octet-stream');
  const safeName = sanitizeFilename(file.original_name);
  const utf8Name = encodeURIComponent(safeName);

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${safeName.replace(/"/g, '')}"; filename*=UTF-8''${utf8Name}`);
  res.setHeader('Content-Length', stat.size);
  res.setHeader('Cache-Control', 'private, max-age=0, no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
  res.setHeader('Referrer-Policy', 'no-referrer');

  logEvent('info', 'file_download', { fileId, qrId: file.qr_id, ip, owner: isOwner, size: stat.size });

  q.run('UPDATE file_uploads SET download_count = download_count + 1 WHERE id = ?', [fileId]).catch(() => {});

  if (path.extname(filePath).toLowerCase() === '.gz' && stat.size < 5_000_000 && file.original_size > 0) {
    const raw = fs.createReadStream(filePath);
    const gunzip = zlib.createGunzip();
    let settled = false;
    const fail = () => { if (!settled && !res.headersSent) { settled = true; res.destroy(); } };
    raw.on('error', fail);
    gunzip.on('error', fail);
    res.on('close', () => { raw.destroy(); gunzip.destroy(); });
    raw.pipe(gunzip).pipe(res);
  } else {
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => { if (!res.headersSent) res.status(500).render('public-error', { message: 'Download failed', code: 500 }); });
    stream.pipe(res);
  }
}));

router.get('/api/verify-code/:qrId', asyncWrap(async (req, res) => {
  const qrId = String(req.params.qrId || '').toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  if (!qr.verify_code_hash) return res.json({ required: false });

  res.json({ required: true });
}));

router.post('/api/verify-code/:qrId', asyncWrap(async (req, res) => {
  const qrId = String(req.params.qrId || '').toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  if (!qr.verify_code_hash) return res.json({ valid: true });

  const code = String(req.body.code || '').trim().substring(0, 200);
  if (!code) return res.status(400).json({ error: 'Code is required' });

  const valid = await bcrypt.compare(code, qr.verify_code_hash);
  if (!valid) {
    logEvent('warn', 'verify_code_fail', { qrId, ip: req.ip });
    return res.status(403).json({ valid: false, error: 'Invalid code' });
  }
  res.json({ valid: true });
}));

module.exports = router;
