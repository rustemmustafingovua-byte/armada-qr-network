const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
process.env.NODE_ENV = process.env.NODE_ENV || 'test';
process.env.BCRYPT_ROUNDS = '4';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'a'.repeat(64);

const { initialize } = require('../db/adapter');
const { sanitize, validateEmail, validateUrl, validateHexColor } = require('../middleware/security');

test.before(async () => { await initialize(); });

test('sanitize strips dangerous characters', () => {
  assert.strictEqual(sanitize('<script>alert(1)</script>'), 'scriptalert(1)/script');
  assert.strictEqual(sanitize('  hello  '), 'hello');
  assert.strictEqual(sanitize(null), '');
  assert.strictEqual(sanitize(123), '');
});

test('validateEmail', () => {
  assert.strictEqual(validateEmail('user@example.com'), true);
  assert.strictEqual(validateEmail('bad@'), false);
  assert.strictEqual(validateEmail(''), false);
  assert.strictEqual(validateEmail('a'.repeat(260) + '@x.com'), false);
});

test('validateUrl', () => {
  assert.strictEqual(validateUrl('https://example.com'), true);
  assert.strictEqual(validateUrl('http://x.y'), true);
  assert.strictEqual(validateUrl('javascript:alert(1)'), false);
  assert.strictEqual(validateUrl('file:///etc/passwd'), false);
  assert.strictEqual(validateUrl('not a url'), false);
  assert.strictEqual(validateUrl(''), false);
});

test('validateHexColor', () => {
  assert.strictEqual(validateHexColor('#000000'), true);
  assert.strictEqual(validateHexColor('#fff'), false);
  assert.strictEqual(validateHexColor('red'), false);
  assert.strictEqual(validateHexColor('#GGGGGG'), false);
});
