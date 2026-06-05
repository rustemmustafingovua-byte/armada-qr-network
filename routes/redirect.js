const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const { q, asyncWrap } = require('../db/query');
const { optionalAuth } = require('../middleware/auth');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');

function sanitizeForPath(str) {
  return str.replace(/\.\.\//g, '').replace(/\.\.\\/g, '').replace(/\0/g, '');
}

function isSafePath(p) {
  return path.resolve(p).startsWith(uploadDir);
}

function parseUserAgent(ua) {
  if (!ua) return { device_type: 'Unknown', os: 'Unknown', browser: 'Unknown' };
  ua = ua.toLowerCase();
  let device_type = 'Desktop', os = 'Unknown', browser = 'Unknown';
  if (/mobile|android.*mobile|iphone|ipod|blackberry/i.test(ua)) device_type = 'Mobile';
  else if (/ipad|tablet|playbook|silk/i.test(ua) || (/android/i.test(ua) && !/mobile/i.test(ua))) device_type = 'Tablet';
  if (/windows/i.test(ua)) os = 'Windows';
  else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  else if (/linux/i.test(ua)) os = 'Linux';
  if (/chrome/i.test(ua) && !/edg|opr/i.test(ua)) browser = 'Chrome';
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/edg/i.test(ua)) browser = 'Edge';
  else if (/opr|opera/i.test(ua)) browser = 'Opera';
  return { device_type, os, browser };
}

function getCountry(ip) {
  if (!ip) return { country: 'Unknown', city: 'Unknown' };
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return { country: 'Local', city: 'Local' };
  return { country: 'Unknown', city: 'Unknown' };
}

async function logScan(qrId, ip, ua, referer) {
  try {
    const info = parseUserAgent(ua);
    const geo = getCountry(ip);
    await Promise.all([
      q.run('INSERT INTO analytics (qr_id, ip_address, user_agent, country, city, device_type, os, browser, referer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [qrId, ip || '', (ua || '').substring(0, 500), geo.country, geo.city, info.device_type, info.os, info.browser, (referer || '').substring(0, 500)]),
      q.run('UPDATE qr_codes SET scan_count = scan_count + 1 WHERE id = ?', [qrId])
    ]);
  } catch (e) {
    console.error('Analytics error:', e.message);
  }
}

async function getQr(id) {
  const cleaned = (id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!cleaned || cleaned.length < 6) return null;
  return q.get('SELECT * FROM qr_codes WHERE id = ?', [cleaned]);
}

router.get('/q/:id', optionalAuth, asyncWrap(async (req, res) => {
  const qr = await getQr(req.params.id);
  if (!qr) return res.status(404).render('public-error', { message: 'QR code not found', code: 404 });
  if (!qr.is_active) return res.render('public-expired', { reason: 'This QR code has been deactivated.' });
  if (qr.expires_at && new Date(qr.expires_at) < new Date()) return res.render('public-expired', { reason: 'This QR code has expired.' });
  if (qr.scan_limit && qr.scan_count >= qr.scan_limit) return res.render('public-expired', { reason: 'This QR code has reached its scan limit.' });
  if (qr.password_hash) {
    if (req.query.pwd) {
      const match = await bcrypt.compare(req.query.pwd, qr.password_hash);
      if (match) { await logScan(qr.id, req.ip, req.get('User-Agent'), req.get('Referer')); return handleContent(req, res, qr); }
    }
    return res.render('public-password', { qrId: qr.id, title: qr.title || '' });
  }
  await logScan(qr.id, req.ip, req.get('User-Agent'), req.get('Referer'));
  return handleContent(req, res, qr);
}));

router.post('/q/:id', asyncWrap(async (req, res) => {
  const qr = await getQr(req.params.id);
  if (!qr) return res.status(404).render('public-error', { message: 'QR code not found', code: 404 });
  if (qr.password_hash) {
    const pwd = (req.body.password || '').substring(0, 256);
    const match = await bcrypt.compare(pwd, qr.password_hash);
    if (!match) return res.render('public-password', { qrId: qr.id, title: qr.title || '', error: 'Invalid password' });
    await logScan(qr.id, req.ip, req.get('User-Agent'), req.get('Referer'));
    return handleContent(req, res, qr);
  }
  res.redirect(`/q/${qr.id}`);
}));

async function getFiles(qrId) {
  return q.all('SELECT id, original_name, original_size, mime_type, created_at FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC', [qrId]);
}

async function getFileCount(qrId) {
  const row = await q.get('SELECT COUNT(*) as count FROM file_uploads WHERE qr_id = ?', [qrId]);
  return parseInt(row?.count || 0);
}

function handleContent(req, res, qr) {
  switch (qr.content_type) {
    case 'link': {
      const url = qr.target_url || '/';
      if (url.startsWith('http://') || url.startsWith('https://')) return res.redirect(302, url);
      return res.redirect(302, '/');
    }
    case 'file':
      return handleFileContent(req, res, qr);
    case 'vcard':
      res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${(qr.title || 'contact').replace(/[^a-zA-Z0-9_-]/g, '_')}.vcf"`);
      return res.send(qr.vcard_data || '');
    case 'text':
      return res.render('public-text', { text: qr.text_data || '', title: qr.title || '', qrId: qr.id });
    default:
      return res.redirect(302, '/');
  }
}

async function handleFileContent(req, res, qr) {
  const files = await getFiles(qr.id);
  const hasVerifyCode = !!qr.verify_code_hash;
  res.render('public-file', {
    title: qr.title || 'File Download',
    qrId: qr.id,
    files,
    hasVerifyCode,
    verified: !!req.query.verified
  });
}

router.get('/download/:id', asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.status(404).render('public-error', { message: 'File not found', code: 404 });

  const files = await q.all('SELECT id FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC LIMIT 1', [id]);
  if (files.length === 0) {
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ?', [id]);
    if (!qr || qr.content_type !== 'file' || !qr.file_path) return res.status(404).render('public-error', { message: 'File not found', code: 404 });
    const safePath = sanitizeForPath(qr.file_path);
    const filePath = path.join(uploadDir, safePath);
    if (!isSafePath(filePath) || !fs.existsSync(filePath)) return res.status(404).render('public-error', { message: 'File not found', code: 404 });
    const ext = path.extname(qr.file_name || '').toLowerCase();
    const fileName = qr.file_name || 'download';
    const stat = fs.statSync(filePath);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName.replace(/[<>:"/\\|?*]/g, '_')}"`);
    res.setHeader('Content-Length', stat.size);
    res.setHeader('Cache-Control', 'no-cache');
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
    return;
  }

  res.redirect(`/d/${files[0].id}`);
}));

module.exports = router;
