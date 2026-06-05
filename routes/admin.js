const express = require('express');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'admin') return res.status(403).redirect('/dashboard');
  next();
}

router.get('/admin', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const [users, totalQrsRow, totalScansRow, activeScansRow, qrs, scansByDay] = await Promise.all([
    q.all('SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC'),
    q.get('SELECT COUNT(*) as count FROM qr_codes'),
    q.get('SELECT COUNT(*) as count FROM analytics'),
    q.get("SELECT COUNT(*) as count FROM analytics WHERE scanned_at >= DATE('now', '-24 hours')"),
    q.all('SELECT q.id, q.title, q.type, q.scan_count, q.is_active, q.created_at, u.email as owner_email FROM qr_codes q JOIN users u ON q.user_id = u.id ORDER BY q.created_at DESC LIMIT 50'),
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE scanned_at >= DATE('now', '-14 days') GROUP BY date ORDER BY date"),
  ]);

  res.render('admin', {
    users, qrs, totalQrs: parseInt(totalQrsRow?.count || 0),
    totalScans: parseInt(totalScansRow?.count || 0),
    totalUsers: users.length,
    activeScans: parseInt(activeScansRow?.count || 0),
    scansByDay: JSON.stringify(scansByDay),
    user: req.user,
  });
}));

router.post('/admin/user/:id/toggle-admin', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id || id === req.user.id) return res.redirect('/admin');
  const target = await q.get('SELECT * FROM users WHERE id = ?', [id]);
  if (!target) return res.redirect('/admin');
  const newRole = target.role === 'admin' ? 'user' : 'admin';
  await q.run('UPDATE users SET role = ? WHERE id = ?', [newRole, id]);
  res.redirect('/admin');
}));

router.post('/admin/user/:id/delete', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id || id === req.user.id) return res.redirect('/admin');
  await q.run('DELETE FROM users WHERE id = ?', [id]);
  res.redirect('/admin');
}));

router.post('/admin/qr/:id/delete', requireAuth, requireAdmin, asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.redirect('/admin');
  await q.run('DELETE FROM qr_codes WHERE id = ?', [id]);
  res.redirect('/admin');
}));

module.exports = router;
