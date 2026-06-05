const crypto = require('crypto');

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>"'&]/g, '').trim();
}

function validateEmail(email) {
  if (typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validateId(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{6,36}$/.test(id);
}

function validateUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

function validateHexColor(color) {
  return /^#[0-9a-fA-F]{6}$/.test(color);
}

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function csrfProtection(req, res, next) {
  if (!req.session) req.session = {};
  if (!req.session.csrfToken) req.session.csrfToken = generateCsrfToken();
  if (req.method === 'GET') {
    res.locals.csrfToken = req.session.csrfToken;
    return next();
  }
  const token = req.body && req.body._csrf;
  if (!token || token !== req.session.csrfToken) {
    return res.status(403).send('CSRF token invalid');
  }
  req.session.csrfToken = generateCsrfToken();
  next();
}

module.exports = { sanitize, validateEmail, validateId, validateUrl, validateHexColor, generateCsrfToken, csrfProtection };
