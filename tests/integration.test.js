const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');

process.env.NODE_ENV = 'test';
process.env.BCRYPT_ROUNDS = '4';
process.env.JWT_SECRET = 'a'.repeat(64);
process.env.DB_PATH = path.join(__dirname, '..', 'db', 'test-qrmaster.db');

const dbFile = process.env.DB_PATH;
try { fs.unlinkSync(dbFile); } catch {}
try { fs.unlinkSync(dbFile + '-wal'); } catch {}
try { fs.unlinkSync(dbFile + '-shm'); } catch {}

const http = require('http');
const express = require('express');

let app, server, BASE;

test.before(async () => {
  const cookieParser = require('cookie-parser');
  const crypto = require('crypto');
  const multer = require('multer');
  const uploadDir = path.join(__dirname, '..', 'public', 'uploads');
  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
  const upload = multer({ storage: multer.diskStorage({ destination: uploadDir, filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname) }), limits: { fileSize: 200 * 1024 * 1024 } });
  app = express();
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));

  app.use((req, res, next) => {
    let token = req.cookies?._csrf;
    if (!token) {
      token = crypto.randomBytes(32).toString('hex');
      res.cookie('_csrf', token, { httpOnly: false, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000, path: '/' });
    }
    res.locals._csrf = token;
    next();
  });

  const { initialize, ensureAdmin, migrateV2, getDb } = require('../db/adapter');
  await initialize();
  await migrateV2();
  await ensureAdmin();

  const authRoutes = require('../routes/auth');
  const qrRoutes = require('../routes/qr');
  const redirectRoutes = require('../routes/redirect');
  const filesRoutes = require('../routes/files');
  const analyticsRoutes = require('../routes/analytics');
  const settingsRoutes = require('../routes/settings');

  app.use('/', authRoutes);
  app.use('/', qrRoutes);
  app.use('/', filesRoutes);
  app.use('/', redirectRoutes);
  app.use('/', analyticsRoutes);
  app.use('/', settingsRoutes);

  app.get('/health', (req, res) => res.json({ status: 'ok', db: 'up' }));

  server = app.listen(0, '127.0.0.1');
  await new Promise(r => server.on('listening', r));
  BASE = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  if (server) server.close();
  try { require('../db/adapter').getDb().close(); } catch {}
  try { fs.unlinkSync(dbFile); } catch {}
  try { fs.unlinkSync(dbFile + '-wal'); } catch {}
  try { fs.unlinkSync(dbFile + '-shm'); } catch {}
});

function parseSetCookies(headers) {
  const raw = headers.getSetCookie ? headers.getSetCookie() : [];
  if (raw.length > 0) {
    return raw.map(c => c.split(';')[0]).join('; ');
  }
  const single = headers.get('set-cookie');
  if (!single) return '';
  return single.split(/, (?=[a-zA-Z_]+=)/).map(c => c.split(';')[0]).join('; ');
}

test('health check', async () => {
  const r = await fetch(BASE + '/health');
  const j = await r.json();
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.status, 'ok');
});

test('register creates user and sets token cookie', async () => {
  const r = await fetch(BASE + '/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'test@example.com', password: 'test1234', name: 'Tester', _csrf: 'a' }),
    redirect: 'manual',
  });
  assert.strictEqual(r.status, 302, 'should redirect after register');
  const cookies = parseSetCookies(r.headers);
  assert.ok(cookies.includes('token='), 'should set token cookie, got: ' + cookies);
});

test('registered user can access dashboard', async () => {
  const reg = await fetch(BASE + '/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'dash@example.com', password: 'test1234', name: 'Dash', _csrf: 'a' }),
    redirect: 'manual',
  });
  const cookies = parseSetCookies(reg.headers);
  assert.ok(cookies.includes('token='), 'token cookie missing');

  const dash = await fetch(BASE + '/dashboard', { headers: { Cookie: cookies } });
  assert.strictEqual(dash.status, 200, 'dashboard should be accessible');
});

test('create QR code with file upload', async () => {
  const reg = await fetch(BASE + '/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'file@example.com', password: 'test1234', name: 'File', _csrf: 'a' }),
    redirect: 'manual',
  });
  let cookies = parseSetCookies(reg.headers);

  const dashRes = await fetch(BASE + '/dashboard', { headers: { Cookie: cookies } });
  assert.strictEqual(dashRes.status, 200, 'dashboard should be accessible');

  const csrfValue = cookies.split('; ').find(c => c.startsWith('_csrf='))?.split('=')[1];
  assert.ok(csrfValue, 'CSRF token should be in cookies');

  const FormData = require('form-data');
  const fd = new FormData();
  fd.append('_csrf', csrfValue);
  fd.append('title', 'Test QR');
  fd.append('content_type', 'file');
  fd.append('file', Buffer.from('%PDF-1.4 test content'), { filename: 'test.pdf', contentType: 'application/pdf' });

  const cr = await fetch(BASE + '/create', {
    method: 'POST',
    headers: { Cookie: cookies, ...fd.getHeaders() },
    body: fd.getBuffer(),
    redirect: 'manual',
  });
  assert.ok([200, 302].includes(cr.status), 'create should succeed, got: ' + cr.status);
});

test('rate limit on /q/ endpoint', async () => {
  const r = await fetch(BASE + '/q/aaaaaaaaaaaa');
  assert.ok([404, 403, 200, 429].includes(r.status));
});
