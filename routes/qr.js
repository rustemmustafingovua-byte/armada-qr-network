const express = require('express');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');
const multer = require('multer');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
const { getPublicUrl } = require('../utils/network');
const { sanitize, validateUrl, validateHexColor } = require('../middleware/security');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');

function csrfCheckSync(req) {
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== req.cookies?._csrf) {
    const e = new Error('Invalid CSRF token');
    e.status = 403; e.csrf = true;
    return e;
  }
}

// QR image memory cache (TTL 5 min)
const qrCache = new Map();
const CACHE_TTL = 300000;
function getCachedQr(key) {
  const entry = qrCache.get(key);
  if (entry && Date.now() - entry.ts < CACHE_TTL) return entry.data;
  qrCache.delete(key);
  return null;
}
function setCachedQr(key, data) {
  qrCache.set(key, { data, ts: Date.now() });
  if (qrCache.size > 500) {
    const oldest = [...qrCache.entries()].sort((a, b) => a[1].ts - b[1].ts)[0];
    if (oldest) qrCache.delete(oldest[0]);
  }
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext || '.bin'}`);
  }
});
const upload = multer({
  storage, limits: { fileSize: 200 * 1024 * 1024 },
});

function compressFile(srcPath) {
  return new Promise((resolve, reject) => {
    const tmpPath = srcPath + '.tmp';
    const gzip = zlib.createGzip({ level: 6 });
    const inp = fs.createReadStream(srcPath);
    const out = fs.createWriteStream(tmpPath);
    inp.pipe(gzip).pipe(out);
    out.on('finish', () => {
      fs.unlinkSync(srcPath);
      fs.renameSync(tmpPath, srcPath);
      resolve();
    });
    out.on('error', reject);
    gzip.on('error', reject);
  });
}

router.get('/dashboard', requireAuth, asyncWrap(async (req, res) => {
  const qrs = await q.all('SELECT * FROM qr_codes WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.render('dashboard', { qrs, user: req.user });
}));

router.get('/create', requireAuth, (req, res) => {
  res.render('create', { user: req.user, error: null });
});

router.post('/create', requireAuth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.render('create', { user: req.user, error: 'Upload error: ' + err.message });
    const csrfErr = (() => { try { return csrfCheckSync(req); } catch(e) { return e; } })();
    if (csrfErr) return next(csrfErr);
    handleCreate(req, res);
  });
});

async function handleCreate(req, res) {
  try {
    const title = sanitize(req.body.title || '').substring(0, 200);
    const type = req.body.type === 'static' ? 'static' : 'dynamic';
    const content_type = ['link', 'file', 'vcard', 'text'].includes(req.body.content_type) ? req.body.content_type : 'link';
    const target_url = req.body.target_url ? sanitize(req.body.target_url).substring(0, 2048) : '';
    const vcard_data = req.body.vcard_data || '';
    const text_data = req.body.text_data || '';
    const password = req.body.password || '';
    const verifyCode = req.body.verify_code || '';
    const expires_at = req.body.expires_at || null;
    const scan_limit = req.body.scan_limit ? Math.min(parseInt(req.body.scan_limit) || 0, 999999) : null;
    const fg_color = validateHexColor(req.body.fg_color) ? req.body.fg_color : '#000000';
    const bg_color = validateHexColor(req.body.bg_color) ? req.body.bg_color : '#FFFFFF';
    const dot_style = ['square', 'rounded', 'circle'].includes(req.body.dot_style) ? req.body.dot_style : 'square';

    if (type === 'dynamic' && content_type === 'link' && target_url && !validateUrl(target_url)) {
      return res.render('create', { user: req.user, error: 'Invalid URL format' });
    }

    const id = uuidv4().replace(/-/g, '').substring(0, 12);

    let password_hash = null;
    if (password) {
      if (password.length < 3) return res.render('create', { user: req.user, error: 'Password too short' });
      password_hash = await bcrypt.hash(password, 10);
    }

    let verify_code_hash = null;
    if (verifyCode) {
      if (verifyCode.length < 3) return res.render('create', { user: req.user, error: 'Verification code too short (min 3 characters)' });
      verify_code_hash = await bcrypt.hash(verifyCode, 10);
    }

    let filePath = '';
    let fileName = '';
    let fileSize = 0;
    if (req.file) {
      filePath = req.file.filename;
      fileName = Buffer.from(req.file.originalname, 'latin1').toString('utf8').replace(/[<>:"/\\|?*]/g, '_');
      const rawPath = path.join(uploadDir, filePath);
      fileSize = fs.statSync(rawPath).size;
      await compressFile(rawPath);
      const compressedSize = fs.statSync(rawPath).size;
      await q.run(
        'INSERT INTO file_uploads (qr_id, file_path, original_name, mime_type, original_size, compressed_size) VALUES (?, ?, ?, ?, ?, ?)',
        [id, filePath, fileName, req.file.mimetype || 'application/octet-stream', fileSize, compressedSize]
      );
    }

    await q.run(
      `INSERT INTO qr_codes (id, user_id, title, type, content_type, target_url, file_path, file_name, vcard_data, text_data, password_hash, verify_code_hash, expires_at, scan_limit, fg_color, bg_color, dot_style, file_size)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.user.id, title, type, content_type, target_url, filePath, fileName, vcard_data, text_data, password_hash, verify_code_hash, expires_at, scan_limit, fg_color, bg_color, dot_style, fileSize]
    );

    const baseUrl = getPublicUrl(req);
    const qrUrl = type === 'static'
      ? (content_type === 'text' ? text_data : target_url)
      : `${baseUrl}/q/${id}`;
    const qrImage = await QRCode.toDataURL(qrUrl, {
      color: { dark: fg_color, light: bg_color },
      errorCorrectionLevel: 'M'
    });

    res.render('create-result', { id, qrImage, qrUrl, baseUrl, title, verifyCode, user: req.user });
  } catch (err) {
    console.error('Create error:', err);
    res.render('create', { user: req.user, error: 'Failed to create QR code: ' + err.message });
  }
}

router.get('/edit/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.redirect('/dashboard');
  res.render('edit', { qr, user: req.user, error: null });
}));

router.post('/edit/:id', requireAuth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) return res.render('edit', { qr: null, user: req.user, error: 'Upload error: ' + err.message });
    const csrfErr = (() => { try { return csrfCheckSync(req); } catch(e) { return e; } })();
    if (csrfErr) return next(csrfErr);
    handleEdit(req, res);
  });
});

async function handleEdit(req, res) {
  try {
    if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!qr) return res.redirect('/dashboard');

    const title = sanitize(req.body.title || '').substring(0, 200);
    const target_url = sanitize(req.body.target_url || '').substring(0, 2048);
    const vcard_data = req.body.vcard_data || '';
    const text_data = req.body.text_data || '';
    const password = req.body.password || '';
    const verifyCode = req.body.verify_code || '';
    const expires_at = req.body.expires_at || null;
    const scan_limit = req.body.scan_limit ? Math.min(parseInt(req.body.scan_limit) || 0, 999999) : null;
    const is_active = req.body.is_active !== undefined ? 1 : 0;
    const fg_color = validateHexColor(req.body.fg_color) ? req.body.fg_color : qr.fg_color;
    const bg_color = validateHexColor(req.body.bg_color) ? req.body.bg_color : qr.bg_color;
    const dot_style = ['square', 'rounded', 'circle'].includes(req.body.dot_style) ? req.body.dot_style : qr.dot_style;

    let password_hash = qr.password_hash;
    if (password) {
      if (password.length < 3) return res.render('edit', { qr, user: req.user, error: 'Password too short' });
      password_hash = await bcrypt.hash(password, 10);
    }

    let verify_code_hash = qr.verify_code_hash;
    if (verifyCode) {
      if (verifyCode.length < 3) return res.render('edit', { qr, user: req.user, error: 'Verification code too short' });
      verify_code_hash = await bcrypt.hash(verifyCode, 10);
    }

    let filePath = qr.file_path;
    let fileName = qr.file_name;
    let fileSize = qr.file_size || 0;
    if (req.file) {
      filePath = req.file.filename;
      fileName = Buffer.from(req.file.originalname, 'latin1').toString('utf8').replace(/[<>:"/\\|?*]/g, '_');
      const rawPath = path.join(uploadDir, filePath);
      fileSize = fs.statSync(rawPath).size;
      await compressFile(rawPath);
      const compressedSize = fs.statSync(rawPath).size;
      await q.run(
        'INSERT INTO file_uploads (qr_id, file_path, original_name, mime_type, original_size, compressed_size) VALUES (?, ?, ?, ?, ?, ?)',
        [req.params.id, filePath, fileName, req.file.mimetype || 'application/octet-stream', fileSize, compressedSize]
      );
    }

    await q.run(
      `UPDATE qr_codes SET title=?, target_url=?, file_path=?, file_name=?, vcard_data=?, text_data=?, password_hash=?, verify_code_hash=?, expires_at=?, scan_limit=?, is_active=?, fg_color=?, bg_color=?, dot_style=?, file_size=?, updated_at=CURRENT_TIMESTAMP
       WHERE id=? AND user_id=?`,
      [title, target_url, filePath, fileName, vcard_data, text_data, password_hash, verify_code_hash, expires_at, scan_limit, is_active, fg_color, bg_color, dot_style, fileSize, req.params.id, req.user.id]
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Edit error:', err);
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.render('edit', { qr, user: req.user, error: 'Update failed' });
  }
}

router.post('/delete/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
  qrCache.delete(req.params.id);
  const files = await q.all('SELECT file_path FROM file_uploads WHERE qr_id = ?', [req.params.id]);
  for (const f of files) {
    try { fs.unlinkSync(path.join(uploadDir, f.file_path)); } catch {}
  }
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (qr && qr.file_path) {
    try { fs.unlinkSync(path.join(uploadDir, qr.file_path)); } catch {}
  }
  await q.run('DELETE FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  res.redirect('/dashboard');
}));

router.get('/qr-image/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.status(404).send('Not found');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.status(404).send('Not found');
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static'
    ? (qr.content_type === 'text' ? qr.text_data : qr.target_url)
    : `${baseUrl}/q/${qr.id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, {
    color: { dark: qr.fg_color, light: qr.bg_color },
    errorCorrectionLevel: 'M'
  });
  res.json({ image: qrImage, url: qrUrl });
}));

router.post('/generate-qr', requireAuth, asyncWrap(async (req, res) => {
  const qrId = req.body.qrId || '';
  if (!/^[a-f0-9]{12}$/i.test(qrId)) return res.status(400).json({ error: 'Invalid ID' });
  let cached = getCachedQr(qrId);
  if (cached) return res.json({ image: cached.image, url: cached.url });
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [qrId, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static'
    ? (qr.content_type === 'text' ? qr.text_data : qr.target_url)
    : `${baseUrl}/q/${qr.id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, {
    color: { dark: qr.fg_color, light: qr.bg_color },
    margin: 2, width: 400, errorCorrectionLevel: 'M'
  });
  setCachedQr(qrId, { image: qrImage, url: qrUrl });
  res.json({ image: qrImage, url: qrUrl });
}));

module.exports = router;
