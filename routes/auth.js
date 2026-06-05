const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { q, asyncWrap } = require('../db/query');
const { generateToken, setTokenCookie, clearTokenCookie } = require('../middleware/auth');
const { sanitize, validateEmail } = require('../middleware/security');

const router = express.Router();

router.get('/login', (req, res) => {
  if (req.cookies?.token) {
    try { jwt.verify(req.cookies.token, process.env.JWT_SECRET); return res.redirect('/dashboard'); } catch {}
  }
  res.render('login', { error: null });
});

router.get('/register', (req, res) => {
  if (req.cookies?.token) {
    try { jwt.verify(req.cookies.token, process.env.JWT_SECRET); return res.redirect('/dashboard'); } catch {}
  }
  res.render('register', { error: null });
});

router.post('/register', asyncWrap(async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';
  const name = sanitize(req.body.name || '').substring(0, 100);

  if (!email) return res.render('register', { error: 'Email is required' });
  if (!validateEmail(email)) return res.render('register', { error: 'Invalid email address' });
  if (password.length < 6) return res.render('register', { error: 'Password must be at least 6 characters' });
  if (password.length > 128) return res.render('register', { error: 'Password too long (max 128)' });

  const existing = await q.get('SELECT id FROM users WHERE email = ?', [email]);
  if (existing) return res.render('register', { error: 'Email already registered. <a href="/login" class="text-indigo-600 hover:underline">Sign in</a>' });

  const hash = await bcrypt.hash(password, 12);
  await q.run('INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)', [email, hash, name]);

  const user = await q.get('SELECT * FROM users WHERE email = ?', [email]);
  const adminCount = await q.get("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
  if (parseInt(adminCount.count) === 0) {
    await q.run('UPDATE users SET role = ? WHERE id = ?', ['admin', user.id]);
    user.role = 'admin';
  }

  const token = generateToken(user);
  setTokenCookie(res, token);
  res.redirect('/dashboard');
}));

router.post('/login', asyncWrap(async (req, res) => {
  const email = (req.body.email || '').toLowerCase().trim();
  const password = req.body.password || '';

  if (!email || !password) return res.render('login', { error: 'Email and password required' });

  const user = await q.get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user) return res.render('login', { error: 'Invalid email or password' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.render('login', { error: 'Invalid email or password' });

  const token = generateToken(user);
  setTokenCookie(res, token);
  res.redirect('/dashboard');
}));

router.get('/logout', (req, res) => {
  clearTokenCookie(res);
  res.redirect('/login');
});

module.exports = router;
