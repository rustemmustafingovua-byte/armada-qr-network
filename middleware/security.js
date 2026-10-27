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

module.exports = { sanitize, validateEmail, validateId, validateUrl, validateHexColor };
