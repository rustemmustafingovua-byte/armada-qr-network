const express = require('express');
const QRCode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const zlib = require('zlib');
const crypto = require('crypto');
const multer = require('multer');
const { q, asyncWrap, db } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
const { getPublicUrl } = require('../utils/network');
const { sanitize, validateUrl, validateHexColor } = require('../middleware/security');
const { logEvent, audit } = require('../utils/logger');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const MAX_FILE_SIZE = 200 * 1024 * 1024;

function csrfCheckSync(req) {
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== req.cookies?._csrf) {
    return Object.assign(new Error('Invalid CSRF token'), { status: 403, csrf: true });
  }
}

const qrCache = new Map();
const CACHE_TTL = 300_000;
const CACHE_MAX = 1000;

function getCachedQr(key) {
  const entry = qrCache.get(key);
  if (entry && Date.now() - entry.ts < CACHE_TTL) return entry.data;
  qrCache.delete(key);
  return null;
}
function setCachedQr(key, data) {
  qrCache.set(key, { data, ts: Date.now() });
  if (qrCache.size > CACHE_MAX) {
    const arr = [...qrCache.entries()].sort((a, b) => a[1].ts - b[1].ts);
    for (let i = 0; i < 200; i++) qrCache.delete(arr[i][0]);
  }
}
function invalidateQrCache(id) { qrCache.delete(id); }

const STORAGE = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '').toLowerCase().replace(/[^a-z0-9.]/g, '').substring(0, 10) || '.bin';
    cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
  }
});
const upload = multer({
  storage: STORAGE,
  limits: { fileSize: MAX_FILE_SIZE, files: 1, fields: 30, fieldSize: 200_000 }
});

const MAGIC_BYTES = {
  pdf: [0x25, 0x50, 0x44, 0x46],
  png: [0x89, 0x50, 0x4E, 0x47],
  jpg: [0xFF, 0xD8, 0xFF],
  gif: [0x47, 0x49, 0x46],
  zip: [0x50, 0x4B, 0x03, 0x04],
  rar: [0x52, 0x61, 0x72, 0x21],
  gz: [0x1F, 0x8B],
  '7z': [0x37, 0x7A, 0xBC, 0xAF],
};

function detectMime(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(8);
    fs.readSync(fd, buf, 0, 8, 0);
    fs.closeSync(fd);
    for (const [type, sig] of Object.entries(MAGIC_BYTES)) {
      if (sig.every((b, i) => buf[i] === b)) {
        const map = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', gif: 'image/gif', zip: 'application/zip', rar: 'application/vnd.rar', gz: 'application/gzip', '7z': 'application/x-7z-compressed' };
        return map[type];
      }
    }
  } catch {}
  return null;
}

function compressFile(srcPath) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(srcPath)) return reject(new Error('Source not found'));
    const stat = fs.statSync(srcPath);
    if (stat.size < 256) return resolve({ originalSize: stat.size, compressedSize: stat.size });
    const tmpPath = srcPath + '.tmp.' + crypto.randomBytes(4).toString('hex');
    const gzip = zlib.createGzip({ level: 6 });
    const inp = fs.createReadStream(srcPath);
    const out = fs.createWriteStream(tmpPath);
    let settled = false;
    const fail = (err) => { if (settled) return; settled = true; try { fs.unlinkSync(tmpPath); } catch {} reject(err); };
    const done = () => {
      if (settled) return;
      settled = true;
      try { fs.unlinkSync(srcPath); fs.renameSync(tmpPath, srcPath); resolve({ originalSize: stat.size, compressedSize: fs.statSync(srcPath).size }); }
      catch (e) { fail(e); }
    };
    out.on('finish', done);
    out.on('error', fail);
    gzip.on('error', fail);
    inp.on('error', fail);
    inp.pipe(gzip).pipe(out);
  });
}

function decodeFilename(name) {
  if (!name) return '';
  try { name = Buffer.from(name, 'latin1').toString('utf8'); } catch {}
  return String(name).replace(/[\x00-\x1f\x7f<>:"|?*\\\/]/g, '_').trim().substring(0, 200);
}

router.get('/dashboard', requireAuth, asyncWrap(async (req, res) => {
  const qrs = await q.all(
    `SELECT q.*,
       (SELECT COUNT(*) FROM qr_messages WHERE qr_id = q.id AND is_read = 0) as unread_count,
       (SELECT COUNT(*) FROM file_uploads WHERE qr_id = q.id) as file_count
     FROM qr_codes q
     WHERE user_id = ?
     ORDER BY created_at DESC
     LIMIT 500`,
    [req.user.id]
  );
  const messages = {
    updated: 'QR code updated.',
    deleted: 'QR code deleted.',
    bulk_deleted: 'Selected QR codes deleted.'
  };
  res.render('dashboard', { qrs, user: req.user, success: messages[req.query.success] || null, error: req.query.error || null, activePage: 'dashboard' });
}));

router.get('/create', requireAuth, (req, res) => {
  res.render('create', { user: req.user, error: null, form: {}, activePage: 'create' });
});

router.post('/create', requireAuth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      logEvent('warn', 'upload_error', { msg: err.message, code: err.code });
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large (max 200 MB)' : 'Upload error: ' + err.message;
      return res.render('create', { user: req.user, error: msg, form: req.body || {} });
    }
    const csrfErr = csrfCheckSync(req);
    if (csrfErr) return next(csrfErr);
    handleCreate(req, res);
  });
});

async function handleCreate(req, res) {
  try {
    const body = req.body || {};
    const title = sanitize(body.title || '').substring(0, 200);
    const type = body.type === 'static' ? 'static' : 'dynamic';
    const allowedContent = ['link', 'file', 'vcard', 'text', 'wifi', 'event'];
    const content_type = allowedContent.includes(body.content_type) ? body.content_type : 'link';
    const target_url = body.target_url ? sanitize(body.target_url).substring(0, 2048) : '';
    const vcard_data = (body.vcard_data || '').substring(0, 5000);
    const text_data = (body.text_data || '').substring(0, 5000);
    const wifi_ssid = sanitize(body.wifi_ssid || '').substring(0, 100);
    const wifi_password = (body.wifi_password || '').substring(0, 200);
    const wifi_encryption = ['WPA', 'WEP', 'nopass'].includes(body.wifi_encryption) ? body.wifi_encryption : 'WPA';
    const wifi_hidden = body.wifi_hidden === 'on' || body.wifi_hidden === '1' ? 1 : 0;
    const event_title = sanitize(body.event_title || '').substring(0, 200);
    const event_location = sanitize(body.event_location || '').substring(0, 300);
    const event_start = body.event_start || null;
    const event_end = body.event_end || null;
    const event_description = sanitize(body.event_description || '').substring(0, 2000);
    const password = (body.password || '').substring(0, 128);
    const verifyCode = (body.verify_code || '').substring(0, 128);
    const expires_at = body.expires_at || null;
    const scan_limit = body.scan_limit ? Math.min(parseInt(body.scan_limit) || 0, 9_999_999) : null;
    const fg_color = validateHexColor(body.fg_color) ? body.fg_color : '#000000';
    const bg_color = validateHexColor(body.bg_color) ? body.bg_color : '#FFFFFF';
    const dot_style = ['square', 'rounded', 'circle', 'dot', 'classy'].includes(body.dot_style) ? body.dot_style : 'square';
    const webhook_url = (body.webhook_url || '').substring(0, 500);
    const tags = sanitize(body.tags || '').substring(0, 500);
    const notes = sanitize(body.notes || '').substring(0, 2000);
    const is_active = body.is_active === 'on' || body.is_active === '1' || body.is_active === undefined ? 1 : 0;

    if (!title.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Title is required', form: body });
    }
    if (type === 'dynamic' && content_type === 'link' && target_url && !validateUrl(target_url)) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Invalid URL. Must start with http:// or https://', form: body });
    }
    if (content_type === 'link' && !target_url.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'URL is required for link type', form: body });
    }
    if (content_type === 'file' && !req.file) {
      return res.render('create', { user: req.user, error: 'Please select a file to upload', form: body });
    }
    if (content_type === 'vcard' && !vcard_data.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'vCard data is required', form: body });
    }
    if (content_type === 'text' && !text_data.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Text content is required', form: body });
    }
    if (content_type === 'wifi' && !wifi_ssid.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'WiFi SSID is required', form: body });
    }
    if (content_type === 'event' && !event_title.trim()) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Event title is required', form: body });
    }
    if (password && password.length < 3) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Password too short (min 3 characters)', form: body });
    }
    if (verifyCode && verifyCode.length < 3) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Verification code too short (min 3 characters)', form: body });
    }
    if (webhook_url && !validateUrl(webhook_url)) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Invalid webhook URL', form: body });
    }
    if (expires_at && isNaN(Date.parse(expires_at))) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Invalid expiry date', form: body });
    }
    if (scan_limit !== null && scan_limit < 0) {
      cleanupUpload(req.file);
      return res.render('create', { user: req.user, error: 'Scan limit cannot be negative', form: body });
    }

    const id = uuidv4().replace(/-/g, '').substring(0, 12);
    const password_hash = password ? await bcrypt.hash(password, BCRYPT_ROUNDS) : null;
    const verify_code_hash = verifyCode ? await bcrypt.hash(verifyCode, BCRYPT_ROUNDS) : null;

    let filePath = '';
    let fileName = '';
    let fileSize = 0;
    if (req.file) {
      filePath = req.file.filename;
      fileName = decodeFilename(req.file.originalname);
      fileSize = fs.statSync(req.file.path).size;
    }

    await q.run(
      `INSERT INTO qr_codes (id, user_id, title, type, content_type, target_url, file_path, file_name, vcard_data, text_data,
        wifi_ssid, wifi_password, wifi_encryption, wifi_hidden,
        event_title, event_location, event_start, event_end, event_description,
        password_hash, verify_code_hash, expires_at, scan_limit,
        fg_color, bg_color, dot_style, file_size, webhook_url, tags, notes, is_active)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [id, req.user.id, title, type, content_type, target_url, filePath, fileName, vcard_data, text_data,
       wifi_ssid, wifi_password, wifi_encryption, wifi_hidden,
       event_title, event_location, event_start, event_end, event_description,
       password_hash, verify_code_hash, expires_at, scan_limit,
       fg_color, bg_color, dot_style, fileSize, webhook_url, tags, notes, is_active]
    );

    const uploadedFiles = [];
    if (req.file) {
      let compressed;
      try {
        compressed = await compressFile(req.file.path);
      } catch (e) {
        logEvent('error', 'compress_failed', { file: req.file.path, msg: e.message });
        await q.run('DELETE FROM qr_codes WHERE id = ?', [id]);
        cleanupUpload(req.file);
        return res.render('create', { user: req.user, error: 'File processing failed', form: body });
      }
      const detectedMime = detectMime(req.file.path) || req.file.mimetype || 'application/octet-stream';
      const ins = await q.run(
        'INSERT INTO file_uploads (qr_id, file_path, original_name, mime_type, original_size, compressed_size) VALUES (?, ?, ?, ?, ?, ?)',
        [id, filePath, fileName, detectedMime, fileSize, compressed.compressedSize]
      );
      const fileId = db.type === 'postgres' ? (ins?.rows?.[0]?.id || 0) : (ins?.lastInsertRowid || 0);
      uploadedFiles.push({ id: fileId, original_name: fileName, original_size: fileSize, mime_type: detectedMime });
    }

    const baseUrl = getPublicUrl(req);
    const qrUrl = type === 'static'
      ? (content_type === 'text' ? text_data : content_type === 'vcard' ? target_url : target_url)
      : `${baseUrl}/q/${id}`;

    const qrImage = await QRCode.toDataURL(qrUrl, {
      color: { dark: fg_color, light: bg_color },
      errorCorrectionLevel: dot_style === 'logo' ? 'H' : 'M',
      width: 400,
      margin: 2
    });

    audit(req.user.id, 'qr_created', { qrId: id, content_type, has_file: !!req.file, has_password: !!password, has_verify: !!verifyCode });

    res.render('create-result', {
      id, qrImage, qrUrl, baseUrl, title, verifyCode, password,
      uploadedFiles, user: req.user, content_type, type,
      success: true
    });
  } catch (err) {
    logEvent('error', 'create_error', { msg: err.message, stack: err.stack });
    cleanupUpload(req.file);
    res.render('create', { user: req.user, error: 'Failed to create QR code: ' + err.message, form: req.body || {} });
  }
}

function cleanupUpload(file) {
  if (file?.path) { try { fs.unlinkSync(file.path); } catch {} }
}

router.get('/edit/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.redirect('/dashboard');
  res.render('edit', { qr, user: req.user, error: null, success: null, activePage: 'create' });
}));

router.post('/edit/:id', requireAuth, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      logEvent('warn', 'edit_upload_error', { msg: err.message });
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File too large (max 200 MB)' : 'Upload error: ' + err.message;
      return res.status(400).render('edit', { qr: null, user: req.user, error: msg, success: null });
    }
    const csrfErr = csrfCheckSync(req);
    if (csrfErr) return next(csrfErr);
    handleEdit(req, res);
  });
});

async function handleEdit(req, res) {
  try {
    if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!qr) return res.redirect('/dashboard');

    const body = req.body || {};
    const title = sanitize(body.title || '').substring(0, 200);
    const target_url = sanitize(body.target_url || '').substring(0, 2048);
    const vcard_data = (body.vcard_data || '').substring(0, 5000);
    const text_data = (body.text_data || '').substring(0, 5000);
    const wifi_ssid = sanitize(body.wifi_ssid || '').substring(0, 100);
    const wifi_password = (body.wifi_password || '').substring(0, 200);
    const wifi_encryption = ['WPA', 'WEP', 'nopass'].includes(body.wifi_encryption) ? body.wifi_encryption : qr.wifi_encryption;
    const wifi_hidden = body.wifi_hidden === 'on' ? 1 : 0;
    const event_title = sanitize(body.event_title || '').substring(0, 200);
    const event_location = sanitize(body.event_location || '').substring(0, 300);
    const event_start = body.event_start || null;
    const event_end = body.event_end || null;
    const event_description = sanitize(body.event_description || '').substring(0, 2000);
    const password = (body.password || '').substring(0, 128);
    const verifyCode = (body.verify_code || '').substring(0, 128);
    const expires_at = body.expires_at || null;
    const scan_limit = body.scan_limit ? Math.min(parseInt(body.scan_limit) || 0, 9_999_999) : null;
    const is_active = body.is_active === 'on' || body.is_active === '1' ? 1 : 0;
    const fg_color = validateHexColor(body.fg_color) ? body.fg_color : qr.fg_color;
    const bg_color = validateHexColor(body.bg_color) ? body.bg_color : qr.bg_color;
    const dot_style = ['square', 'rounded', 'circle', 'dot', 'classy'].includes(body.dot_style) ? body.dot_style : qr.dot_style;
    const webhook_url = (body.webhook_url || '').substring(0, 500);
    const tags = sanitize(body.tags || '').substring(0, 500);
    const notes = sanitize(body.notes || '').substring(0, 2000);

    if (contentTypeRequiresFile(qr.content_type) && !req.file && !qr.file_path) {
      return res.render('edit', { qr, user: req.user, error: 'This QR code requires a file', success: null });
    }

    let password_hash = qr.password_hash;
    if (password === '__clear__') password_hash = '';
    else if (password) {
      if (password.length < 3) return res.render('edit', { qr, user: req.user, error: 'Password too short', success: null });
      password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    }
    let verify_code_hash = qr.verify_code_hash;
    if (verifyCode === '__clear__') verify_code_hash = '';
    else if (verifyCode) {
      if (verifyCode.length < 3) return res.render('edit', { qr, user: req.user, error: 'Verification code too short', success: null });
      verify_code_hash = await bcrypt.hash(verifyCode, BCRYPT_ROUNDS);
    }

    let filePath = qr.file_path;
    let fileName = qr.file_name;
    let fileSize = qr.file_size || 0;
    let replacedFilePath = null;
    if (req.file) {
      const oldFilePath = qr.file_path;
      filePath = req.file.filename;
      fileName = decodeFilename(req.file.originalname);
      fileSize = fs.statSync(req.file.path).size;
      try {
        const compressed = await compressFile(req.file.path);
        const detectedMime = detectMime(req.file.path) || req.file.mimetype || 'application/octet-stream';
        await q.run(
          'INSERT INTO file_uploads (qr_id, file_path, original_name, mime_type, original_size, compressed_size) VALUES (?, ?, ?, ?, ?, ?)',
          [req.params.id, filePath, fileName, detectedMime, fileSize, compressed.compressedSize]
        );
        replacedFilePath = oldFilePath;
      } catch (e) {
        logEvent('error', 'edit_compress_failed', { msg: e.message });
        cleanupUpload(req.file);
        return res.render('edit', { qr, user: req.user, error: 'File processing failed', success: null });
      }
    }

    await q.run(
      `UPDATE qr_codes SET
        title=?, target_url=?, file_path=?, file_name=?, vcard_data=?, text_data=?,
        wifi_ssid=?, wifi_password=?, wifi_encryption=?, wifi_hidden=?,
        event_title=?, event_location=?, event_start=?, event_end=?, event_description=?,
        password_hash=?, verify_code_hash=?, expires_at=?, scan_limit=?, is_active=?,
        fg_color=?, bg_color=?, dot_style=?, file_size=?, webhook_url=?, tags=?, notes=?,
        updated_at=CURRENT_TIMESTAMP
       WHERE id=? AND user_id=?`,
      [title, target_url, filePath, fileName, vcard_data, text_data,
       wifi_ssid, wifi_password, wifi_encryption, wifi_hidden,
       event_title, event_location, event_start, event_end, event_description,
       password_hash, verify_code_hash, expires_at, scan_limit, is_active,
       fg_color, bg_color, dot_style, fileSize, webhook_url, tags, notes,
       req.params.id, req.user.id]
    );

    if (replacedFilePath) {
      try { fs.unlinkSync(path.join(uploadDir, replacedFilePath)); } catch {}
    }

    invalidateQrCache(req.params.id);
    audit(req.user.id, 'qr_updated', { qrId: req.params.id, file_replaced: !!req.file });
    res.redirect('/dashboard?success=updated');
  } catch (err) {
    logEvent('error', 'edit_error', { msg: err.message });
    cleanupUpload(req.file);
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.render('edit', { qr, user: req.user, error: 'Update failed: ' + err.message, success: null });
  }
}

function contentTypeRequiresFile(ct) { return ct === 'file'; }

router.post('/delete/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
  const csrfErr = csrfCheckSync(req);
  if (csrfErr) return res.redirect('/dashboard');
  const files = await q.all('SELECT file_path FROM file_uploads WHERE qr_id = ?', [req.params.id]);
  for (const f of files) {
    try { fs.unlinkSync(path.join(uploadDir, f.file_path)); } catch {}
  }
  const qr = await q.get('SELECT file_path FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (qr?.file_path) {
    try { fs.unlinkSync(path.join(uploadDir, qr.file_path)); } catch {}
  }
  await q.run('DELETE FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  invalidateQrCache(req.params.id);
  audit(req.user.id, 'qr_deleted', { qrId: req.params.id });
  res.redirect('/dashboard?success=deleted');
}));

router.post('/delete-bulk', requireAuth, asyncWrap(async (req, res) => {
  const csrfErr = csrfCheckSync(req);
  if (csrfErr) return res.redirect('/dashboard');
  const ids = Array.isArray(req.body.ids) ? req.body.ids : (req.body.ids ? [req.body.ids] : []);
  const clean = ids.map(id => String(id).toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12)).filter(id => /^[a-f0-9]{12}$/.test(id));
  if (clean.length === 0) return res.redirect('/dashboard');
  if (clean.length > 100) return res.redirect('/dashboard?error=too_many');
  const placeholders = clean.map(() => '?').join(',');
  const files = await q.all(`SELECT file_path, qr_id FROM file_uploads WHERE qr_id IN (${placeholders})`, clean);
  for (const f of files) {
    try { fs.unlinkSync(path.join(uploadDir, f.file_path)); } catch {}
  }
  const qrs = await q.all(`SELECT file_path FROM qr_codes WHERE user_id = ? AND id IN (${placeholders})`, [req.user.id, ...clean]);
  for (const f of qrs) {
    if (f.file_path) { try { fs.unlinkSync(path.join(uploadDir, f.file_path)); } catch {} }
  }
  await q.run(`DELETE FROM qr_codes WHERE user_id = ? AND id IN (${placeholders})`, [req.user.id, ...clean]);
  clean.forEach(invalidateQrCache);
  audit(req.user.id, 'qr_bulk_deleted', { count: clean.length });
  res.redirect('/dashboard?success=bulk_deleted');
}));

router.post('/toggle-active/:id', requireAuth, asyncWrap(async (req, res) => {
  const csrfErr = csrfCheckSync(req);
  if (csrfErr) return res.redirect('/dashboard');
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.redirect('/dashboard');
  await q.run('UPDATE qr_codes SET is_active = 1 - is_active WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  invalidateQrCache(req.params.id);
  res.redirect('/dashboard');
}));

router.get('/qr-image/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.status(404).json({ error: 'Not found' });
  const cached = getCachedQr(req.params.id);
  if (cached) return res.json({ image: cached.image, url: cached.url, cached: true });
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static' ? (qr.content_type === 'text' ? qr.text_data : qr.target_url) : `${baseUrl}/q/${qr.id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, { color: { dark: qr.fg_color, light: qr.bg_color }, errorCorrectionLevel: 'M', width: 400, margin: 2 });
  setCachedQr(req.params.id, { image: qrImage, url: qrUrl });
  res.json({ image: qrImage, url: qrUrl, cached: false });
}));

router.get('/qr-image-public/:id', asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.status(404).send('Not found');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ?', [req.params.id]);
  if (!qr) return res.status(404).send('Not found');
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static' ? (qr.content_type === 'text' ? qr.text_data : qr.target_url) : `${baseUrl}/q/${qr.id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, { color: { dark: qr.fg_color, light: qr.bg_color }, errorCorrectionLevel: 'M', width: 600, margin: 2 });
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  const data = qrImage.replace(/^data:image\/png;base64,/, '');
  res.end(Buffer.from(data, 'base64'));
}));

router.get('/qr-svg/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.status(404).send('Not found');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.status(404).send('Not found');
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static' ? (qr.content_type === 'text' ? qr.text_data : qr.target_url) : `${baseUrl}/q/${qr.id}`;
  const svg = await QRCode.toString(qrUrl, { type: 'svg', color: { dark: qr.fg_color, light: qr.bg_color }, errorCorrectionLevel: 'M', margin: 2 });
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Content-Disposition', `attachment; filename="qr-${qr.id}.svg"`);
  res.setHeader('Cache-Control', 'private, no-cache');
  res.send(svg);
}));

router.get('/qr-png/:id', requireAuth, asyncWrap(async (req, res) => {
  if (!/^[a-f0-9]{12}$/i.test(req.params.id)) return res.status(404).send('Not found');
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  if (!qr) return res.status(404).send('Not found');
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static' ? (qr.content_type === 'text' ? qr.text_data : qr.target_url) : `${baseUrl}/q/${qr.id}`;
  const buffer = await QRCode.toBuffer(qrUrl, { type: 'png', color: { dark: qr.fg_color, light: qr.bg_color }, errorCorrectionLevel: 'M', width: 1024, margin: 2 });
  res.setHeader('Content-Type', 'image/png');
  res.setHeader('Content-Disposition', `attachment; filename="qr-${qr.id}.png"`);
  res.setHeader('Content-Length', buffer.length);
  res.end(buffer);
}));

router.post('/generate-qr', requireAuth, asyncWrap(async (req, res) => {
  const qrId = String(req.body.qrId || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(qrId)) return res.status(400).json({ error: 'Invalid ID' });
  const cached = getCachedQr(qrId);
  if (cached) return res.json({ image: cached.image, url: cached.url, cached: true });
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [qrId, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  const baseUrl = getPublicUrl(req);
  const qrUrl = qr.type === 'static' ? (qr.content_type === 'text' ? qr.text_data : qr.target_url) : `${baseUrl}/q/${qr.id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, { color: { dark: qr.fg_color, light: qr.bg_color }, margin: 2, width: 400, errorCorrectionLevel: 'M' });
  setCachedQr(qrId, { image: qrImage, url: qrUrl });
  res.json({ image: qrImage, url: qrUrl, cached: false });
}));

module.exports = router;
