const express = require('express');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const CACHE = {};
const CACHE_TTL = 60000;

function cached(key, fn) {
  const now = Date.now();
  if (CACHE[key] && now - CACHE[key].ts < CACHE_TTL) return CACHE[key].data;
  return fn().then(data => { CACHE[key] = { data, ts: now }; return data; });
}

router.get('/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.redirect('/dashboard');

  const qr = await q.get('SELECT id, title, content_type FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.redirect('/dashboard');

  const SCAN_DAYS = 30;
  const [scansByDay, osStats, deviceStats, browserStats, countryStats, totalRow, recentScans] = await Promise.all([
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? AND scanned_at >= DATE('now', ? || ' days') GROUP BY date ORDER BY date", [id, `-${SCAN_DAYS}`]),
    q.all("SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? AND os NOT IN ('Unknown','') GROUP BY os ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? AND device_type NOT IN ('Unknown','') GROUP BY device_type ORDER BY count DESC LIMIT 5", [id]),
    q.all("SELECT browser, COUNT(*) as count FROM analytics WHERE qr_id = ? AND browser NOT IN ('Unknown','') GROUP BY browser ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT country, COUNT(*) as count FROM analytics WHERE qr_id = ? AND country NOT IN ('Unknown','') GROUP BY country ORDER BY count DESC LIMIT 20", [id]),
    q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id]),
    q.all('SELECT scanned_at, device_type, os, browser, country, ip_address FROM analytics WHERE qr_id = ? ORDER BY scanned_at DESC LIMIT 50', [id]),
  ]);

  res.render('analytics', {
    qr, user: req.user,
    totalScans: parseInt(totalRow?.total || 0),
    scansByDay: JSON.stringify(scansByDay),
    osStats: JSON.stringify(osStats),
    deviceStats: JSON.stringify(deviceStats),
    browserStats: JSON.stringify(browserStats),
    countryStats: JSON.stringify(countryStats),
    recentScans
  });
}));

router.get('/api/analytics-summary', requireAuth, asyncWrap(async (req, res) => {
  const summary = await cached(`sum_${req.user.id}`, () => Promise.all([
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM analytics a JOIN qr_codes q ON a.qr_id = q.id WHERE q.user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ? AND is_active = 1', [req.user.id]),
    q.get('SELECT q.title, COUNT(a.id) as scans FROM qr_codes q LEFT JOIN analytics a ON q.id = a.qr_id WHERE q.user_id = ? GROUP BY q.id ORDER BY scans DESC LIMIT 1', [req.user.id]),
  ]).then(([totalQrsRow, totalScansRow, activeQrsRow, topQr]) => ({
    totalQrs: parseInt(totalQrsRow?.count || 0),
    totalScans: parseInt(totalScansRow?.count || 0),
    activeQrs: parseInt(activeQrsRow?.count || 0),
    topQr: topQr || null,
  })));

  res.json(summary);
}));

router.get('/api/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = (req.params.id || '').replace(/[^a-fA-F0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.status(404).json({ error: 'Not found' });

  const data = await cached(`api_${id}`, () => Promise.all([
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? AND scanned_at >= DATE('now', '-30 days') GROUP BY date ORDER BY date", [id]),
    q.all("SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? AND os NOT IN ('Unknown','') GROUP BY os ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? AND device_type NOT IN ('Unknown','') GROUP BY device_type ORDER BY count DESC LIMIT 5", [id]),
    q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id]),
  ]).then(([scansByDay, osStats, deviceStats, totalRow]) => ({
    totalScans: parseInt(totalRow?.total || 0),
    scansByDay, osStats, deviceStats
  })));

  res.json(data);
}));

module.exports = router;
