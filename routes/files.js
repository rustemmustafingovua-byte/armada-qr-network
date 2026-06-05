const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const { promisify } = require('util');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');

const mimeTypes = {
  '.pdf': 'application/pdf',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.mp3': 'audio/mpeg', '.mp4': 'video/mp4', '.wav': 'audio/wav', '.ogg': 'audio/ogg',
  '.doc': 'application/msword', '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.zip': 'application/zip', '.rar': 'application/vnd.rar', '.7z': 'application/x-7z-compressed', '.gz': 'application/gzip', '.tar': 'application/x-tar',
  '.txt': 'text/plain', '.csv': 'text/csv', '.json': 'application/json', '.xml': 'application/xml',
  '.js': 'application/javascript', '.css': 'text/css', '.html': 'text/html',
  '.mp4': 'video/mp4', '.mov': 'video/quicktime', '.avi': 'video/x-msvideo', '.mkv': 'video/x-matroska',
  '.exe': 'application/x-msdownload', '.dmg': 'application/x-apple-diskimage', '.deb': 'application/x-debian-package',
  '.iso': 'application/x-iso9660-image',
};

async function verifyCode(qr, code) {
  if (!qr.verify_code_hash) return true;
  if (!code) return false;
  return bcrypt.compare(code, qr.verify_code_hash);
}

router.get('/files/:qrId', asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(404).json({ error: 'Not found' });

  const qr = await q.get('SELECT id, verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });

  const files = await q.all(
    'SELECT id, original_name, original_size, mime_type, created_at FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC',
    [qrId]
  );

  res.json({ files });
}));

router.get('/d/:fileId', asyncWrap(async (req, res) => {
  const fileId = parseInt(req.params.fileId);
  if (!fileId) return res.status(404).render('public-error', { message: 'File not found', code: 404 });

  const file = await q.get(
    'SELECT f.*, q.verify_code_hash, q.is_active FROM file_uploads f JOIN qr_codes q ON f.qr_id = q.id WHERE f.id = ?',
    [fileId]
  );
  if (!file) return res.status(404).render('public-error', { message: 'File not found', code: 404 });
  if (!file.is_active) return res.render('public-expired', { reason: 'This QR code has been deactivated.' });

  const code = req.query.code || req.body?.code || '';
  if (file.verify_code_hash) {
    const valid = await bcrypt.compare(code, file.verify_code_hash);
    if (!valid) {
      if (req.xhr || req.path.startsWith('/api/')) return res.status(403).json({ error: 'Invalid verification code' });
      return res.render('public-error', { message: 'Invalid verification code', code: 403 });
    }
  }

  const filePath = path.join(uploadDir, file.file_path);
  if (!fs.existsSync(filePath)) return res.status(404).render('public-error', { message: 'File not found', code: 404 });

  const ext = path.extname(file.original_name).toLowerCase();
  const contentType = mimeTypes[ext] || 'application/octet-stream';
  const encodedName = encodeURIComponent(file.original_name);

  res.setHeader('Content-Type', contentType);
  res.setHeader('Content-Disposition', `attachment; filename="${file.original_name.replace(/[<>:"/\\|?*]/g, '_')}"; filename*=UTF-8''${encodedName}`);
  res.setHeader('Content-Length', file.original_size);
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const raw = fs.createReadStream(filePath);
  const gunzip = zlib.createGunzip();
  raw.pipe(gunzip).pipe(res);

  raw.on('error', () => { if (!res.headersSent) res.status(500).render('public-error', { message: 'Download failed', code: 500 }); });
  gunzip.on('error', () => { if (!res.headersSent) res.status(500).render('public-error', { message: 'Download failed', code: 500 }); });
}));

router.get('/api/verify-code/:qrId', asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  if (!qr.verify_code_hash) return res.json({ required: false });

  res.json({ required: true });
}));

router.post('/api/verify-code/:qrId', asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT verify_code_hash FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  if (!qr.verify_code_hash) return res.json({ valid: true });

  const code = (req.body.code || '').trim();
  if (!code) return res.status(400).json({ error: 'Code is required' });

  const valid = await bcrypt.compare(code, qr.verify_code_hash);
  if (!valid) return res.json({ valid: false, error: 'Invalid code' });

  res.json({ valid: true });
}));

module.exports = router;
