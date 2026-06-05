const express = require('express');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
const { logEvent, audit } = require('../utils/logger');

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'admin') return res.status(403).redirect('/dashboard');
  next();
}

function csrfCheck(req) {
  return (req.headers['x-csrf-token'] || req.body?._csrf) === req.cookies?._csrf;
}

router.get('/admin', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const [users, totalQrsRow, totalScansRow, activeScansRow, qrs, scansByDay, totalFilesRow, totalMessagesRow] = await Promise.all([
    q.all('SELECT id, email, name, role, totp_enabled, created_at FROM users ORDER BY created_at DESC'),
    q.get('SELECT COUNT(*) as count FROM qr_codes'),
    q.get('SELECT COUNT(*) as count FROM analytics'),
    q.get("SELECT COUNT(*) as count FROM analytics WHERE scanned_at >= DATE('now', '-24 hours')"),
    q.all('SELECT q.id, q.title, q.type, q.content_type, q.scan_count, q.is_active, q.created_at, u.email as owner_email FROM qr_codes q JOIN users u ON q.user_id = u.id ORDER BY q.created_at DESC LIMIT 100'),
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE scanned_at >= DATE('now', '-30 days') GROUP BY date ORDER BY date"),
    q.get('SELECT COUNT(*) as count FROM file_uploads'),
    q.get('SELECT COUNT(*) as count FROM qr_messages')
  ]);

  res.render('admin', {
    users, qrs,
    totalQrs: parseInt(totalQrsRow?.count || 0),
    totalScans: parseInt(totalScansRow?.count || 0),
    totalFiles: parseInt(totalFilesRow?.count || 0),
    totalMessages: parseInt(totalMessagesRow?.count || 0),
    totalUsers: users.length,
    activeScans: parseInt(activeScansRow?.count || 0),
    scansByDay: JSON.stringify(scansByDay),
    user: req.user,
  });
}));

router.post('/admin/user/:id/toggle-admin', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).redirect('/admin');
  const id = parseInt(req.params.id);
  if (!id || id === req.user.id) return res.redirect('/admin');
  const target = await q.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!target) return res.redirect('/admin');
  const newRole = target.role === 'admin' ? 'user' : 'admin';
  await q.run('UPDATE users SET role = ? WHERE id = ?', [newRole, id]);
  audit(req.user.id, 'admin_toggled', { targetId: id, newRole });
  res.redirect('/admin');
}));

router.post('/admin/user/:id/delete', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).redirect('/admin');
  const id = parseInt(req.params.id);
  if (!id || id === req.user.id) return res.redirect('/admin');
  await q.run('DELETE FROM users WHERE id = ?', [id]);
  audit(req.user.id, 'user_deleted', { targetId: id });
  res.redirect('/admin');
}));

router.post('/admin/qr/:id/delete', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).redirect('/admin');
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.redirect('/admin');
  await q.run('DELETE FROM qr_codes WHERE id = ?', [id]);
  audit(req.user.id, 'admin_qr_deleted', { id });
  res.redirect('/admin');
}));

router.get('/admin/audit', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const entries = await q.all(
    'SELECT a.*, u.email FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 200'
  );
  res.render('admin-audit', { user: req.user, entries });
}));

module.exports = router;
