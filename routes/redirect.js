const express = require('express');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { q, asyncWrap } = require('../db/query');
const { optionalAuth } = require('../middleware/auth');
const { logEvent, audit } = require('../utils/logger');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const uploadDir = path.resolve(__dirname, '..', process.env.UPLOAD_DIR || './public/uploads');

const UA_CACHE = new Map();
function parseUserAgent(ua) {
  if (!ua) return { device_type: 'Unknown', os: 'Unknown', browser: 'Unknown' };
  const cached = UA_CACHE.get(ua);
  if (cached) return cached;
  const l = ua.toLowerCase();
  let device_type = 'Desktop', os = 'Unknown', browser = 'Unknown';
  if (/tablet|ipad|playbook|silk/i.test(l) || (/android/i.test(l) && !/mobile/i.test(l))) device_type = 'Tablet';
  else if (/mobile|iphone|ipod|blackberry|opera mini/i.test(l)) device_type = 'Mobile';
  if (/windows nt/i.test(l)) os = 'Windows';
  else if (/android/i.test(l)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(l)) os = 'iOS';
  else if (/macintosh|mac os x/i.test(l)) os = 'macOS';
  else if (/cros/i.test(l)) os = 'ChromeOS';
  else if (/linux/i.test(l)) os = 'Linux';
  if (/edg\//i.test(l)) browser = 'Edge';
  else if (/opr\//i.test(l) || /opera/i.test(l)) browser = 'Opera';
  else if (/firefox\//i.test(l)) browser = 'Firefox';
  else if (/chrome\//i.test(l) && !/edg/i.test(l)) browser = 'Chrome';
  else if (/safari\//i.test(l) && !/chrome/i.test(l)) browser = 'Safari';
  const result = { device_type, os, browser };
  if (UA_CACHE.size > 5000) UA_CACHE.clear();
  UA_CACHE.set(ua, result);
  return result;
}

function getCountry(ip) {
  if (!ip) return { country: 'Unknown', city: 'Unknown' };
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
    return { country: 'Local', city: 'Local' };
  }
  return { country: 'Unknown', city: 'Unknown' };
}

function getClientIp(req) {
  return (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.headers['x-real-ip'] || req.ip || '';
}

async function logScan(qrId, ip, ua, referer) {
  try {
    const info = parseUserAgent(ua);
    const geo = getCountry(ip);
    const uniqueHash = crypto.createHash('sha256').update(`${ip}|${ua}|${qrId}`).digest('hex').substring(0, 16);
    await Promise.all([
      q.run('INSERT INTO analytics (qr_id, ip_address, user_agent, country, city, device_type, os, browser, referer, unique_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [qrId, ip || '', (ua || '').substring(0, 500), geo.country, geo.city, info.device_type, info.os, info.browser, (referer || '').substring(0, 500), uniqueHash]),
      q.run('UPDATE qr_codes SET scan_count = scan_count + 1 WHERE id = ?', [qrId])
    ]);
  } catch (e) {
    logEvent('error', 'analytics_error', { msg: e.message });
  }
}

const SCAN_BUCKET = new Map();
const SCAN_WINDOW_MS = 60_000;
const SCAN_MAX = 120;
function checkScanRate(ip) {
  const now = Date.now();
  const arr = (SCAN_BUCKET.get(ip) || []).filter(t => now - t < SCAN_WINDOW_MS);
  if (arr.length >= SCAN_MAX) return false;
  arr.push(now);
  SCAN_BUCKET.set(ip, arr);
  if (SCAN_BUCKET.size > 10_000) {
    for (const [k, v] of SCAN_BUCKET) {
      if (!v.some(t => now - t < SCAN_WINDOW_MS)) SCAN_BUCKET.delete(k);
    }
  }
  return true;
}

async function getQr(id) {
  const cleaned = String(id || '').toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12);
  if (!cleaned || cleaned.length < 6) return null;
  return q.get('SELECT * FROM qr_codes WHERE id = ?', [cleaned]);
}

function isOwner(req, qr) {
  return !!(req.user && qr && String(req.user.id) === String(qr.user_id));
}

function checkExpiry(qr) {
  if (!qr.is_active) return 'This QR code has been deactivated.';
  if (qr.expires_at && new Date(qr.expires_at) < new Date()) return 'This QR code has expired.';
  if (qr.scan_limit && qr.scan_count >= qr.scan_limit) return 'This QR code has reached its scan limit.';
  return null;
}

async function triggerWebhook(qr, event, payload) {
  if (!qr.webhook_url) return;
  try {
    const body = JSON.stringify({ event, qr_id: qr.id, timestamp: new Date().toISOString(), ...payload });
    const url = qr.webhook_url;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-QR-Event': event, 'X-QR-Id': qr.id }, body, signal: controller.signal })
      .then(r => q.run('INSERT INTO webhook_deliveries (user_id, qr_id, event, url, payload, response_status, succeeded) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [qr.user_id, qr.id, event, url, body, r.status, r.ok ? 1 : 0]))
      .catch(e => q.run('INSERT INTO webhook_deliveries (user_id, qr_id, event, url, payload, response_status, succeeded) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [qr.user_id, qr.id, event, url, body, 0, 0]))
      .finally(() => clearTimeout(timeout));
  } catch (e) {
    logEvent('warn', 'webhook_dispatch_failed', { msg: e.message });
  }
}

router.get('/q/:id', optionalAuth, asyncWrap(async (req, res) => {
  const ip = getClientIp(req);
  if (!checkScanRate(ip)) return res.status(429).render('public-error', { message: 'Too many requests. Please slow down.', code: 429 });

  const qr = await getQr(req.params.id);
  if (!qr) return res.status(404).render('public-error', { message: 'QR code not found', code: 404 });
  const expiry = checkExpiry(qr);
  if (expiry) return res.render('public-expired', { reason: expiry });

  const owner = isOwner(req, qr);

  if (owner) {
    await logScan(qr.id, ip, req.get('User-Agent'), req.get('Referer'));
    return handleContent(req, res, qr, true);
  }

  if (qr.password_hash) {
    if (req.query.pwd) {
      const match = await bcrypt.compare(String(req.query.pwd), qr.password_hash);
      if (match) {
        await logScan(qr.id, ip, req.get('User-Agent'), req.get('Referer'));
        triggerWebhook(qr, 'scan', { with_password: true });
        return handleContent(req, res, qr, false);
      }
    }
    return res.render('public-password', { qrId: qr.id, title: qr.title || '', error: null });
  }

  await logScan(qr.id, ip, req.get('User-Agent'), req.get('Referer'));
  triggerWebhook(qr, 'scan', { with_password: false });
  return handleContent(req, res, qr, false);
}));

router.post('/q/:id', asyncWrap(async (req, res) => {
  const ip = getClientIp(req);
  const qr = await getQr(req.params.id);
  if (!qr) return res.status(404).render('public-error', { message: 'QR code not found', code: 404 });
  const expiry = checkExpiry(qr);
  if (expiry) return res.render('public-expired', { reason: expiry });

  if (qr.password_hash) {
    const pwd = String(req.body.password || '').substring(0, 256);
    const match = await bcrypt.compare(pwd, qr.password_hash);
    if (!match) {
      logEvent('warn', 'password_fail', { qrId: qr.id, ip });
      return res.render('public-password', { qrId: qr.id, title: qr.title || '', error: 'Invalid password' });
    }
    await logScan(qr.id, ip, req.get('User-Agent'), req.get('Referer'));
    triggerWebhook(qr, 'scan', { with_password: true });
    return handleContent(req, res, qr, false);
  }
  res.redirect(302, `/q/${qr.id}`);
}));

async function getFiles(qrId) {
  return q.all('SELECT id, original_name, original_size, mime_type, created_at FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC', [qrId]);
}

function buildVcard(qr) {
  if (qr.vcard_data && qr.vcard_data.includes('BEGIN:VCARD')) return qr.vcard_data;
  return qr.vcard_data || '';
}

function buildWifiString(qr) {
  const enc = qr.wifi_encryption === 'nopass' ? 'nopass' : qr.wifi_encryption;
  return `WIFI:T:${enc};S:${qr.wifi_ssid || ''};P:${qr.wifi_password || ''};H:${qr.wifi_hidden ? 'true' : 'false'};;`;
}

function buildVEvent(qr) {
  const fmt = (d) => d ? new Date(d).toISOString().replace(/[-:]|\.\d{3}/g, '') : '';
  let ics = 'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Armada QR//EN\r\nBEGIN:VEVENT\r\n';
  ics += `UID:${qr.id}@armada-qr\r\n`;
  ics += `DTSTAMP:${fmt(new Date())}\r\n`;
  if (qr.event_start) ics += `DTSTART:${fmt(qr.event_start)}\r\n`;
  if (qr.event_end) ics += `DTEND:${fmt(qr.event_end)}\r\n`;
  if (qr.event_title) ics += `SUMMARY:${qr.event_title.replace(/[,;\\]/g, m => '\\' + m)}\r\n`;
  if (qr.event_location) ics += `LOCATION:${qr.event_location.replace(/[,;\\]/g, m => '\\' + m)}\r\n`;
  if (qr.event_description) ics += `DESCRIPTION:${qr.event_description.replace(/[,;\\]/g, m => '\\' + m)}\r\n`;
  ics += 'END:VEVENT\r\nEND:VCALENDAR\r\n';
  return ics;
}

function handleContent(req, res, qr, owner) {
  switch (qr.content_type) {
    case 'link': {
      const url = qr.target_url || '/';
      if (url.startsWith('http://') || url.startsWith('https://')) return res.redirect(302, url);
      if (url.startsWith('/')) return res.redirect(302, url);
      return res.redirect(302, 'https://' + url);
    }
    case 'file':
      return handleFileContent(req, res, qr, owner);
    case 'vcard': {
      const vcf = buildVcard(qr);
      res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${(qr.title || 'contact').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 60)}.vcf"`);
      return res.send(vcf);
    }
    case 'text':
      return res.render('public-text', { text: qr.text_data || '', title: qr.title || '', qrId: qr.id, owner });
    case 'wifi': {
      const wifi = buildWifiString(qr);
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.send(wifi);
    }
    case 'event': {
      const ics = buildVEvent(qr);
      res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${(qr.title || 'event').replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 60)}.ics"`);
      return res.send(ics);
    }
    default:
      return res.redirect(302, '/');
  }
}

async function handleFileContent(req, res, qr, owner) {
  const files = await getFiles(qr.id);
  const hasVerifyCode = !!qr.verify_code_hash;
  const verified = owner || req.query.verified === '1' || !!req.cookies?.[`vc_${qr.id}`];
  res.render('public-file', {
    title: qr.title || 'File Download',
    qrId: qr.id,
    files,
    hasVerifyCode,
    verified,
    owner,
    qr
  });
}

router.get('/download/:id', optionalAuth, asyncWrap(async (req, res) => {
  const id = String(req.params.id || '').toLowerCase().replace(/[^a-f0-9]/g, '').substring(0, 12);
  if (!id || id.length < 6) return res.status(404).render('public-error', { message: 'File not found', code: 404 });

  const files = await q.all('SELECT id FROM file_uploads WHERE qr_id = ? ORDER BY created_at ASC LIMIT 1', [id]);
  if (files.length === 0) {
    const qr = await q.get('SELECT * FROM qr_codes WHERE id = ?', [id]);
    if (!qr || qr.content_type !== 'file' || !qr.file_path) return res.status(404).render('public-error', { message: 'File not found', code: 404 });
    if (isOwner(req, qr)) return res.redirect(`/d/${id}?legacy=1`);
    return res.redirect(302, `/q/${id}`);
  }
  res.redirect(302, `/d/${files[0].id}`);
}));

module.exports = router;
