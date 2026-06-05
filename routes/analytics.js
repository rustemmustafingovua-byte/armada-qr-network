const express = require('express');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
const { logEvent, audit } = require('../utils/logger');

const router = express.Router();
const CACHE = new Map();
const CACHE_TTL = 30_000;
const CACHE_MAX = 500;

function cached(key, fn) {
  const now = Date.now();
  const hit = CACHE.get(key);
  if (hit && now - hit.ts < CACHE_TTL) return Promise.resolve(hit.data);
  return fn().then(data => {
    CACHE.set(key, { data, ts: now });
    if (CACHE.size > CACHE_MAX) {
      const arr = [...CACHE.entries()].sort((a, b) => a[1].ts - b[1].ts);
      for (let i = 0; i < 100; i++) CACHE.delete(arr[i][0]);
    }
    return data;
  });
}
function invalidateUserCache(userId) {
  for (const k of CACHE.keys()) {
    if (k.includes(`_${userId}_`)) CACHE.delete(k);
  }
}

router.get('/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.redirect('/dashboard');
  const qr = await q.get('SELECT id, title, content_type, created_at FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.redirect('/dashboard');

  const SCAN_DAYS = 30;
  const [scansByDay, osStats, deviceStats, browserStats, countryStats, totalRow, recentScans, hourlyStats, refererStats, uniqueVisitors] = await Promise.all([
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? AND scanned_at >= DATE('now', ? || ' days') GROUP BY date ORDER BY date", [id, `-${SCAN_DAYS}`]),
    q.all("SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? AND os NOT IN ('Unknown','') GROUP BY os ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? AND device_type NOT IN ('Unknown','') GROUP BY device_type ORDER BY count DESC LIMIT 5", [id]),
    q.all("SELECT browser, COUNT(*) as count FROM analytics WHERE qr_id = ? AND browser NOT IN ('Unknown','') GROUP BY browser ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT country, COUNT(*) as count FROM analytics WHERE qr_id = ? AND country NOT IN ('Unknown','') GROUP BY country ORDER BY count DESC LIMIT 20", [id]),
    q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id]),
    q.all('SELECT scanned_at, device_type, os, browser, country, ip_address, referer FROM analytics WHERE qr_id = ? ORDER BY scanned_at DESC LIMIT 100', [id]),
    q.all("SELECT strftime('%H', scanned_at) as hour, COUNT(*) as count FROM analytics WHERE qr_id = ? GROUP BY hour ORDER BY hour", [id]),
    q.all("SELECT referer, COUNT(*) as count FROM analytics WHERE qr_id = ? AND referer != '' GROUP BY referer ORDER BY count DESC LIMIT 10", [id]),
    q.get("SELECT COUNT(DISTINCT unique_hash) as count FROM analytics WHERE qr_id = ? AND unique_hash != ''", [id])
  ]);

  res.render('analytics', {
    qr, user: req.user,
    totalScans: parseInt(totalRow?.total || 0),
    uniqueScans: parseInt(uniqueVisitors?.count || 0),
    scansByDay: JSON.stringify(scansByDay),
    osStats: JSON.stringify(osStats),
    deviceStats: JSON.stringify(deviceStats),
    browserStats: JSON.stringify(browserStats),
    countryStats,
    hourlyStats: JSON.stringify(hourlyStats),
    refererStats: JSON.stringify(refererStats),
    recentScans
  });
}));

router.get('/api/analytics-summary', requireAuth, asyncWrap(async (req, res) => {
  const summary = await cached(`sum_${req.user.id}`, () => Promise.all([
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM analytics a JOIN qr_codes q ON a.qr_id = q.id WHERE q.user_id = ?', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM qr_codes WHERE user_id = ? AND is_active = 1', [req.user.id]),
    q.get('SELECT q.title, COUNT(a.id) as scans FROM qr_codes q LEFT JOIN analytics a ON q.id = a.qr_id WHERE q.user_id = ? GROUP BY q.id ORDER BY scans DESC LIMIT 1', [req.user.id]),
    q.get('SELECT COUNT(*) as count FROM qr_messages m JOIN qr_codes q ON m.qr_id = q.id WHERE q.user_id = ? AND m.is_read = 0', [req.user.id])
  ]).then(([totalQrsRow, totalScansRow, activeQrsRow, topQr, unreadRow]) => ({
    totalQrs: parseInt(totalQrsRow?.count || 0),
    totalScans: parseInt(totalScansRow?.count || 0),
    activeQrs: parseInt(activeQrsRow?.count || 0),
    topQr: topQr || null,
    unreadMessages: parseInt(unreadRow?.count || 0)
  })));
  res.json(summary);
}));

router.get('/api/analytics/:id', requireAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(404).json({ error: 'Not found' });
  const data = await cached(`api_${id}`, () => Promise.all([
    q.all("SELECT DATE(scanned_at) as date, COUNT(*) as count FROM analytics WHERE qr_id = ? AND scanned_at >= DATE('now', '-30 days') GROUP BY date ORDER BY date", [id]),
    q.all("SELECT os, COUNT(*) as count FROM analytics WHERE qr_id = ? AND os NOT IN ('Unknown','') GROUP BY os ORDER BY count DESC LIMIT 10", [id]),
    q.all("SELECT device_type, COUNT(*) as count FROM analytics WHERE qr_id = ? AND device_type NOT IN ('Unknown','') GROUP BY device_type ORDER BY count DESC LIMIT 5", [id]),
    q.get('SELECT COUNT(*) as total FROM analytics WHERE qr_id = ?', [id])
  ]).then(([scansByDay, osStats, deviceStats, totalRow]) => ({
    totalScans: parseInt(totalRow?.total || 0),
    scansByDay, osStats, deviceStats
  })));
  res.json(data);
}));

router.get('/analytics/:id/export', requireAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(id)) return res.status(404).send('Not found');
  const qr = await q.get('SELECT id, title FROM qr_codes WHERE id = ? AND user_id = ?', [id, req.user.id]);
  if (!qr) return res.status(404).send('Not found');
  const rows = await q.all('SELECT scanned_at, device_type, os, browser, country, city, ip_address, referer FROM analytics WHERE qr_id = ? ORDER BY scanned_at DESC', [id]);
  const csv = ['Time,Device,OS,Browser,Country,City,IP,Referer'];
  for (const r of rows) {
    const esc = (v) => '"' + String(v || '').replace(/"/g, '""') + '"';
    csv.push([esc(r.scanned_at), esc(r.device_type), esc(r.os), esc(r.browser), esc(r.country), esc(r.city), esc(r.ip_address), esc(r.referer)].join(','));
  }
  audit(req.user.id, 'analytics_exported', { qrId: id, count: rows.length });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="analytics-${qr.title || id}.csv"`);
  res.send(csv.join('\n'));
}));

module.exports = router;
