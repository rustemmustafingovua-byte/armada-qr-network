const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const speakeasy = require('speakeasy');
const { q, asyncWrap } = require('../db/query');
const { generateToken, setTokenCookie, clearTokenCookie } = require('../middleware/auth');
const { sanitize, validateEmail } = require('../middleware/security');
const { logEvent, audit } = require('../utils/logger');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const router = express.Router();
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const TOTP_WINDOW = 1;
const MAX_LOGIN_ATTEMPTS = 8;
const LOCKOUT_MS = 15 * 60 * 1000;
const LOGIN_ATTEMPTS = new Map();

function getLoginAttempts(ip) {
  const now = Date.now();
  const entry = LOGIN_ATTEMPTS.get(ip);
  if (!entry) return 0;
  if (now - entry.first > LOCKOUT_MS) { LOGIN_ATTEMPTS.delete(ip); return 0; }
  return entry.count;
}
function recordLoginAttempt(ip, success) {
  if (success) { LOGIN_ATTEMPTS.delete(ip); return; }
  const entry = LOGIN_ATTEMPTS.get(ip) || { first: Date.now(), count: 0 };
  entry.count++;
  LOGIN_ATTEMPTS.set(ip, entry);
}

function verifyTotp(secret, token) {
  if (!secret || !token) return false;
  return speakeasy.totp.verify({ secret, encoding: 'base32', token: String(token), window: TOTP_WINDOW });
}

function tryAuth(req) {
  const token = req.cookies?.token;
  if (!token) return null;
  try { return jwt.verify(token, process.env.JWT_SECRET); } catch { return null; }
}

router.get('/login', (req, res) => {
  if (tryAuth(req)) return res.redirect('/dashboard');
  res.render('login', { error: null, email: '' });
});

router.get('/register', (req, res) => {
  if (tryAuth(req)) return res.redirect('/dashboard');
  res.render('register', { error: null, email: '', name: '' });
});

router.post('/register', asyncWrap(async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim().substring(0, 254);
  const password = String(req.body.password || '');
  const name = sanitize(req.body.name || '').substring(0, 100);

  if (!email) return res.render('register', { error: 'Email is required', email, name });
  if (!validateEmail(email)) return res.render('register', { error: 'Invalid email address', email, name });
  if (password.length < 8) return res.render('register', { error: 'Password must be at least 8 characters', email, name });
  if (password.length > 128) return res.render('register', { error: 'Password too long (max 128)', email, name });
  if (!/[A-Za-z]/.test(password) || !/\d/.test(password)) return res.render('register', { error: 'Password must contain letters and numbers', email, name });

  const existing = await q.get('SELECT id FROM users WHERE email = ?', [email]);
  if (existing) return res.render('register', { error: 'Email already registered. <a href="/login" class="text-indigo-600 hover:underline">Sign in</a>', email, name });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const ins = await q.run('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)', [email, hash, name]);
  const user = await q.get('SELECT * FROM users WHERE id = ?', [dbLastId(ins)]);
  if (!user) return res.render('register', { error: 'Registration failed', email, name });

  const adminCount = await q.get("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
  if (parseInt(adminCount.count) === 0) {
    await q.run('UPDATE users SET role = ? WHERE id = ?', ['admin', user.id]);
    user.role = 'admin';
  }

  audit(user.id, 'user_registered', { email, _ip: req.ip, _ua: req.get('User-Agent') });
  const token = generateToken(user);
  setTokenCookie(res, token);
  res.redirect('/dashboard');
}));

function dbLastId(ins) {
  if (!ins) return null;
  if (ins.lastInsertRowid) return ins.lastInsertRowid;
  if (ins.rows?.[0]?.id) return ins.rows[0].id;
  return null;
}

router.post('/login', asyncWrap(async (req, res) => {
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const totp = String(req.body.totp || '').replace(/\s/g, '');

  const ip = req.ip;
  const attempts = getLoginAttempts(ip);
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    logEvent('warn', 'login_locked', { ip, email });
    return res.status(429).render('login', { error: 'Too many attempts. Try again in 15 minutes.', email });
  }

  if (!email || !password) {
    recordLoginAttempt(ip, false);
    return res.render('login', { error: 'Email and password required', email });
  }

  const user = await q.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user) {
    recordLoginAttempt(ip, false);
    await bcrypt.compare(password, '$2a$10$invalidsaltinvalidsaltinvalidsaltsaltinvalidsaltinvalidsaltinv').catch(() => {});
    return res.render('login', { error: 'Invalid email or password', email });
  }

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) {
    recordLoginAttempt(ip, false);
    logEvent('warn', 'login_fail', { email, ip });
    return res.render('login', { error: 'Invalid email or password', email });
  }

  if (user.totp_enabled) {
    if (!totp) {
      return res.render('login', { error: null, email, requireTotp: true });
    }
    if (!verifyTotp(user.totp_secret, totp)) {
      recordLoginAttempt(ip, false);
      logEvent('warn', 'login_totp_fail', { email, ip });
      return res.render('login', { error: 'Invalid 2FA code', email, requireTotp: true });
    }
  }

  recordLoginAttempt(ip, true);
  audit(user.id, 'login_success', { _ip: req.ip, _ua: req.get('User-Agent') });
  const token = generateToken(user);
  setTokenCookie(res, token);
  res.redirect('/dashboard');
}));

router.get('/logout', (req, res) => {
  const user = tryAuth(req);
  if (user) audit(user.id, 'logout', { _ip: req.ip });
  clearTokenCookie(res);
  res.redirect('/login');
});

module.exports = router;
