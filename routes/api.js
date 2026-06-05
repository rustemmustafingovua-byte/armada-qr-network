const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { q, asyncWrap, db } = require('../db/query');
const { getPublicUrl } = require('../utils/network');
const { sanitize, validateUrl } = require('../middleware/security');
const { logEvent, audit } = require('../utils/logger');

const router = express.Router();

async function apiAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing Bearer token' });
  const raw = auth.substring(7).trim();
  if (!raw.startsWith('armq_')) return res.status(401).json({ error: 'Invalid token format' });
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const token = await q.get('SELECT * FROM api_tokens WHERE token_hash = ?', [hash]);
  if (!token) return res.status(401).json({ error: 'Invalid token' });
  if (token.expires_at && new Date(token.expires_at) < new Date()) return res.status(401).json({ error: 'Token expired' });
  const user = await q.get('SELECT id, email, role FROM users WHERE id = ?', [token.user_id]);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  req.apiToken = token;
  q.run('UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?', [token.id]).catch(() => {});
  next();
}

router.get('/api/v1/qr', apiAuth, asyncWrap(async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const offset = parseInt(req.query.offset) || 0;
  const qrs = await q.all(
    `SELECT id, title, type, content_type, target_url, scan_count, is_active, created_at
     FROM qr_codes WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
    [req.user.id, limit, offset]
  );
  const total = await q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ?', [req.user.id]);
  res.json({ data: qrs, pagination: { limit, offset, total: parseInt(total.count) } });
}));

router.post('/api/v1/qr', apiAuth, asyncWrap(async (req, res) => {
  const body = req.body || {};
  const title = sanitize(body.title || 'Untitled').substring(0, 200);
  if (!title) return res.status(400).json({ error: 'title is required' });
  const type = body.type === 'static' ? 'static' : 'dynamic';
  const contentType = ['link', 'file', 'vcard', 'text', 'wifi', 'event'].includes(body.content_type) ? body.content_type : 'link';
  const targetUrl = body.target_url ? sanitize(body.target_url).substring(0, 2048) : '';
  if (contentType === 'link' && targetUrl && !validateUrl(targetUrl)) return res.status(400).json({ error: 'Invalid URL' });
  if (contentType === 'link' && !targetUrl) return res.status(400).json({ error: 'target_url required for link' });

  const id = crypto.randomBytes(6).toString('hex');
  await q.run(
    `INSERT INTO qr_codes (id, user_id, title, type, content_type, target_url, vcard_data, text_data,
      wifi_ssid, wifi_password, wifi_encryption, event_title, event_location, event_start, event_end, event_description,
      fg_color, bg_color, dot_style, tags, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, req.user.id, title, type, contentType, targetUrl,
     body.vcard_data || '', body.text_data || '',
     body.wifi_ssid || '', body.wifi_password || '', body.wifi_encryption || 'WPA',
     body.event_title || '', body.event_location || '', body.event_start || null, body.event_end || null, body.event_description || '',
     body.fg_color || '#000000', body.bg_color || '#FFFFFF', body.dot_style || 'square',
     body.tags || '', body.notes || '']
  );
  audit(req.user.id, 'api_qr_created', { id, contentType, _ip: req.ip });
  const baseUrl = getPublicUrl(req);
  const qrUrl = type === 'static' ? targetUrl : `${baseUrl}/q/${id}`;
  const qrImage = await QRCode.toDataURL(qrUrl, { color: { dark: body.fg_color || '#000000', light: body.bg_color || '#FFFFFF' }, errorCorrectionLevel: 'M', width: 400 });
  res.status(201).json({ id, qr_url: qrUrl, qr_image: qrImage, type, content_type: contentType });
}));

router.get('/api/v1/qr/:id', apiAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'Not found' });
  const analytics = await q.get('SELECT COUNT(*) as count FROM analytics WHERE qr_id = ?', [id]);
  const messages = await q.get('SELECT COUNT(*) as count FROM qr_messages WHERE qr_id = ?', [id]);
  res.json({ data: { ...qr, scan_count: parseInt(analytics.count), message_count: parseInt(messages.count) } });
}));

router.delete('/api/v1/qr/:id', apiAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const result = await q.run('DELETE FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  audit(req.user.id, 'api_qr_deleted', { id });
  res.status(204).end();
}));

router.get('/api/v1/analytics/:id', apiAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const exists = await q.get('SELECT id FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!exists) return res.status(404).json({ error: 'Not found' });
  const [total, byDay, devices, countries] = await Promise.all([
    q.get('SELECT COUNT(*) as count FROM analytics WHERE qr_id = ?', [id]),
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY date ORDER BY date DESC LIMIT 30", [id]),
    q.all("SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY device_type", [id]),
    q.all("SELECT country, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY country ORDER BY count DESC", [id])
  ]);
  res.json({ total: parseInt(total.count), by_day: byDay, devices, countries });
}));

router.get('/api/v1/messages/:id', apiAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(400).json({ error: 'Invalid ID' });
  const exists = await q.get('SELECT id FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!exists) return res.status(404).json({ error: 'Not found' });
  const messages = await q.all('SELECT * FROM qr_messages WHERE qr_id = ? ORDER BY created_at DESC LIMIT 200', [id]);
  res.json({ data: messages });
}));

module.exports = router;
