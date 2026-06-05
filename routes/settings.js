const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { q, asyncWrap } = require('../db/query');
const { requireAuth } = require('../middleware/auth');
const { sanitize, validateEmail, validateUrl } = require('../middleware/security');
const { logEvent, audit } = require('../utils/logger');
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);

const router = express.Router();

function csrfCheck(req) {
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  return token && token === req.cookies?._csrf;
}

router.get('/settings', requireAuth, asyncWrap(async (req, res) => {
  const user = await q.get('SELECT id, email, name, role, totp_enabled, language, email_notifications, created_at FROM users WHERE id = ?', [req.user.id]);
  const tokens = await q.all('SELECT id, name, prefix, last_used_at, expires_at, created_at FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  const errorMap = {
    invalid_email: 'Invalid email address.',
    email_taken: 'Email already in use.',
    wrong_password: 'Wrong password.',
    password_short: 'Password too short (min 8 chars).',
    password_weak: 'Password must contain letters and numbers.'
  };
  const successMap = {
    updated: 'Profile saved.',
    email_updated: 'Email updated.',
    password_updated: 'Password changed.',
    '2fa_enabled': '2FA enabled.',
    '2fa_disabled': '2FA disabled.',
    token_revoked: 'Token revoked.'
  };
  res.render('settings', {
    user, tokens,
    new_token: req.query.new_token,
    error: errorMap[req.query.error] || (req.query.error ? 'Error: ' + req.query.error : null),
    success: successMap[req.query.success] || (req.query.success ? 'Saved.' : null),
    tab: req.query.tab || 'profile'
  });
}));

router.post('/settings/profile', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const name = sanitize(req.body.name || '').substring(0, 100);
  const language = ['en', 'ru'].includes(req.body.language) ? req.body.language : 'en';
  const emailNotifications = req.body.email_notifications === 'on' ? 1 : 0;
  await q.run('UPDATE users SET name = ?, language = ?, email_notifications = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?', [name, language, emailNotifications, req.user.id]);
  audit(req.user.id, 'profile_updated', { language });
  res.redirect('/settings?tab=profile&success=updated');
}));

router.post('/settings/email', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const newEmail = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  if (!validateEmail(newEmail)) return res.redirect('/settings?tab=profile&error=invalid_email');
  const user = await q.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(password, user.password_hash)) return res.redirect('/settings?tab=profile&error=wrong_password');
  const exists = await q.get('SELECT id FROM users WHERE email = ? AND id != ?', [newEmail, req.user.id]);
  if (exists) return res.redirect('/settings?tab=profile&error=email_taken');
  await q.run('UPDATE users SET email = ? WHERE id = ?', [newEmail, req.user.id]);
  audit(req.user.id, 'email_changed', { newEmail });
  res.redirect('/settings?tab=profile&success=email_updated');
}));

router.post('/settings/password', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const current = String(req.body.current_password || '');
  const next = String(req.body.new_password || '');
  if (next.length < 8) return res.redirect('/settings?tab=security&error=password_short');
  if (!/[A-Za-z]/.test(next) || !/\d/.test(next)) return res.redirect('/settings?tab=security&error=password_weak');
  const user = await q.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(current, user.password_hash)) return res.redirect('/settings?tab=security&error=wrong_password');
  const hash = await bcrypt.hash(next, BCRYPT_ROUNDS);
  await q.run('UPDATE users SET password_hash = ? WHERE id = ?', [hash, req.user.id]);
  audit(req.user.id, 'password_changed', {});
  res.redirect('/settings?tab=security&success=password_updated');
}));

router.post('/settings/2fa/enable', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const secret = speakeasy.generateSecret({ name: `ArmadaQR:${req.user.email || req.user.id}`, length: 20 });
  await q.run('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?', [secret.base32, req.user.id]);
  const otpauth = speakeasy.otpauthURL({ secret: secret.ascii, label: `ArmadaQR:${req.user.email}`, issuer: 'Armada QR Network' });
  const qr = await QRCode.toDataURL(otpauth, { width: 250, margin: 1 });
  res.render('settings-2fa', { user: req.user, secret: secret.base32, qr, error: null });
}));

router.post('/settings/2fa/verify', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const code = String(req.body.code || '').replace(/\s/g, '');
  const user = await q.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  const verified = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: code, window: 1 });
  if (!verified) {
    const otpauth = speakeasy.otpauthURL({ secret: user.totp_secret, label: `ArmadaQR:${user.email}`, issuer: 'Armada QR Network' });
    const qr = await QRCode.toDataURL(otpauth, { width: 250, margin: 1 });
    return res.render('settings-2fa', { user, secret: user.totp_secret, qr, error: 'Invalid code. Try again.' });
  }
  await q.run('UPDATE users SET totp_enabled = 1 WHERE id = ?', [req.user.id]);
  audit(req.user.id, '2fa_enabled', {});
  res.redirect('/settings?tab=security&success=2fa_enabled');
}));

router.post('/settings/2fa/disable', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.redirect('/settings?tab=security');
  const password = String(req.body.password || '');
  const user = await q.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
  if (!bcrypt.compareSync(password, user.password_hash)) return res.redirect('/settings?tab=security&error=wrong_password');
  await q.run('UPDATE users SET totp_enabled = 0, totp_secret = "" WHERE id = ?', [req.user.id]);
  audit(req.user.id, '2fa_disabled', {});
  res.redirect('/settings?tab=security&success=2fa_disabled');
}));

router.post('/settings/tokens', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.status(403).send('Invalid CSRF token');
  const name = sanitize(req.body.name || 'API Token').substring(0, 100) || 'API Token';
  const raw = `armq_${crypto.randomBytes(32).toString('hex')}`;
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const prefix = raw.substring(0, 12);
  await q.run('INSERT INTO api_tokens (user_id, name, token_hash, prefix) VALUES (?, ?, ?, ?)', [req.user.id, name, hash, prefix]);
  audit(req.user.id, 'api_token_created', { name });
  res.redirect(`/settings?tab=tokens&new_token=${encodeURIComponent(raw)}`);
}));

router.post('/settings/tokens/:id/delete', requireAuth, asyncWrap(async (req, res) => {
  if (!csrfCheck(req)) return res.redirect('/settings?tab=tokens');
  const id = parseInt(req.params.id);
  if (!id) return res.redirect('/settings?tab=tokens');
  await q.run('DELETE FROM api_tokens WHERE id = ? AND user_id = ?', [id, req.user.id]);
  audit(req.user.id, 'api_token_revoked', { id });
  res.redirect('/settings?tab=tokens&success=token_revoked');
}));

router.get('/settings/export', requireAuth, asyncWrap(async (req, res) => {
  const user = await q.get('SELECT id, email, name, role, created_at FROM users WHERE id = ?', [req.user.id]);
  const qrs = await q.all('SELECT * FROM qr_codes WHERE user_id = ?', [req.user.id]);
  const analytics = await q.all('SELECT a.* FROM analytics a JOIN qr_codes q ON a.qr_id = q.id WHERE q.user_id = ?', [req.user.id]);
  const messages = await q.all('SELECT m.* FROM qr_messages m JOIN qr_codes q ON m.qr_id = q.id WHERE q.user_id = ?', [req.user.id]);
  const exportData = { exported_at: new Date().toISOString(), user, qr_codes: qrs, analytics, messages };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="armada-export-${new Date().toISOString().substring(0, 10)}.json"`);
  res.json(exportData);
  audit(req.user.id, 'data_exported', {});
}));

module.exports = router;
