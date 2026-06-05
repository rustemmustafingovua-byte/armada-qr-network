const express = require('express');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

router.get('/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.redirect('/dashboard');

  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.redirect('/dashboard');

  const scansByDay = await q.all(
    "SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? AND scanned_at >= DATE('now', '-30 days') GROUP BY date ORDER BY date",
    [id]
  );

  const osStats = await q.all(
    "SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? AND os != 'Unknown' GROUP BY os ORDER BY count DESC",
    [id]
  );

  const deviceStats = await q.all(
    "SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? AND device_type != 'Unknown' GROUP BY device_type ORDER BY count DESC",
    [id]
  );

  const browserStats = await q.all(
    "SELECT browser, COUNT(*) as count FROM analytics WHERE qr_id = ? AND browser != 'Unknown' GROUP BY browser ORDER BY count DESC",
    [id]
  );

  const countryStats = await q.all(
    "SELECT country, COUNT(*) as count FROM analytics WHERE qr_id = ? AND country != 'Unknown' GROUP BY country ORDER BY count DESC",
    [id]
  );

  const totalRow = await q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id]);
  const totalScans = parseInt(totalRow?.total || 0);

  const recentScans = await q.all('SELECT * FROM analytics WHERE qr_id = ? ORDER BY scanned_at DESC LIMIT 50', [id]);

  res.render('analytics', {
    qr, user: req.user, totalScans,
    scansByDay: JSON.stringify(scansByDay),
    osStats: JSON.stringify(osStats),
    deviceStats: JSON.stringify(deviceStats),
    browserStats: JSON.stringify(browserStats),
    countryStats: JSON.stringify(countryStats),
    recentScans
  });
}));

router.get('/api/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.status(404).json({ error: 'Not found' });

  const qr = await q.get('SELECT * FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.status(404).json({ error: 'Not found' });

  const [scansByDay, osStats, deviceStats, totalRow] = await Promise.all([
    q.all('SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY date ORDER BY date', [id]),
    q.all('SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY os ORDER BY count DESC', [id]),
    q.all('SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY device_type ORDER BY count DESC', [id]),
    q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id]),
  ]);

  res.json({ totalScans: parseInt(totalRow?.total || 0), scansByDay, osStats, deviceStats });
}));

router.get('/api/analytics-summary', requireAuth, asyncWrap(async (req, res) => {
  const [totalQrsRow, totalScansRow, activeQrsRow, topQr] = await Promise.all([
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM analytics a JOIN qr_codes q ON a.qr_id = q.id WHERE q.user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ? AND is_active = 1', [req.user.id]),
    q.get('SELECT q.title, COUNT(a.id) as scans FROM qr_codes q LEFT JOIN analytics a ON q.id = a.qr_id WHERE q.user_id = ? GROUP BY q.id ORDER BY scans DESC LIMIT 1', [req.user.id]),
  ]);

  res.json({
    totalQrs: parseInt(totalQrsRow?.count || 0),
    totalScans: parseInt(totalScansRow?.count || 0),
    activeQrs: parseInt(activeQrsRow?.count || 0),
    topQr: topQr || null,
  });
}));

module.exports = router;
