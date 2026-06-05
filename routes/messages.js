const express = require('express');
const path = require('path');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();

router.post('/api/messages/:qrId', asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT id FROM qr_codes WHERE id = ?', [qrId]);
  if (!qr) return res.status(404).json({ error: 'QR not found' });

  const senderName = (req.body.name || 'Anonymous').substring(0, 100);
  const message = (req.body.message || '').substring(0, 2000);
  if (!message.trim()) return res.status(400).json({ error: 'Message is required' });

  await q.run(
    'INSERT INTO qr_messages (qr_id, sender_name, message) VALUES (?, ?, ?)',
    [qrId, senderName, message.trim()]
  );

  const msg = await q.get('SELECT id, sender_name, message, created_at FROM qr_messages WHERE id = last_insert_rowid()');
  res.json({ success: true, message: msg });
}));

router.get('/api/messages/:qrId', requireAuth, asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const qr = await q.get('SELECT id FROM qr_codes WHERE id = ? AND user_id = ?', [qrId, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'QR not found' });

  const messages = await q.all(
    'SELECT id, sender_name, message, is_read, reply, created_at FROM qr_messages WHERE qr_id = ? ORDER BY created_at DESC LIMIT 200',
    [qrId]
  );

  res.json({ messages });
}));

router.get('/api/messages/:qrId/public', asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.status(400).json({ error: 'Invalid QR ID' });

  const messages = await q.all(
    "SELECT id, sender_name, message, reply, created_at FROM qr_messages WHERE qr_id = ? AND (reply != '' OR is_read = 0) ORDER BY created_at ASC LIMIT 100",
    [qrId]
  );

  res.json({ messages });
}));

router.post('/api/messages/read/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  const msg = await q.get(
    'SELECT m.id FROM qr_messages m JOIN qr_codes q ON m.qr_id = q.id WHERE m.id = ? AND q.user_id = ?',
    [id, req.user.id]
  );
  if (!msg) return res.status(404).json({ error: 'Not found' });

  await q.run('UPDATE qr_messages SET is_read = 1 WHERE id = ?', [id]);
  res.json({ success: true });
}));

router.post('/api/messages/reply/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  const msg = await q.get(
    'SELECT m.id FROM qr_messages m JOIN qr_codes q ON m.qr_id = q.id WHERE m.id = ? AND q.user_id = ?',
    [id, req.user.id]
  );
  if (!msg) return res.status(404).json({ error: 'Not found' });

  const reply = (req.body.reply || '').substring(0, 2000);
  if (!reply.trim()) return res.status(400).json({ error: 'Reply is required' });

  await q.run('UPDATE qr_messages SET reply = ?, is_read = 1 WHERE id = ?', [reply.trim(), id]);
  res.json({ success: true });
}));

router.get('/api/messages/:qrId/unread-count', requireAuth, asyncWrap(async (req, res) => {
  const qrId = (req.params.qrId || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!qrId || qrId.length < 6) return res.json({ count: 0 });

  const row = await q.get(
    'SELECT COUNT(*) as count FROM qr_messages m JOIN qr_codes q ON m.qr_id = q.id WHERE m.qr_id = ? AND q.user_id = ? AND m.is_read = 0',
    [qrId, req.user.id]
  );

  res.json({ count: parseInt(row?.count || 0) });
}));

module.exports = router;
