const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '7d';
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, iat: Math.floor(Date.now() / 1000) },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

function setTokenCookie(res, token) {
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: COOKIE_MAX_AGE,
    path: '/'
  });
}

function clearTokenCookie(res) {
  res.cookie('token', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 0, path: '/' });
}

function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) {
    if (req.xhr || req.path.startsWith('/api/') || req.accepts('json') === 'json') {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.redirect('/login');
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (err) {
    clearTokenCookie(res);
    if (req.xhr || req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Session expired' });
    }
    return res.redirect('/login');
  }
}

function optionalAuth(req, res, next) {
  const token = req.cookies?.token;
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch { req.user = null; }
  }
  next();
}

module.exports = { generateToken, setTokenCookie, clearTokenCookie, requireAuth, optionalAuth };
