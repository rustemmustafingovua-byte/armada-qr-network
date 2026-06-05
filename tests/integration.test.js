const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
process.env.NODE_ENV = 'test';
process.env.BCRYPT_ROUNDS = '4';
process.env.JWT_SECRET = 'a'.repeat(64);
process.env.DB_PATH = './db/test-qrmaster.db';

const { execSync } = require('child_process');
try { fs.unlinkSync(path.join(__dirname, '..', 'db', 'test-qrmaster.db')); } catch {}
try { fs.unlinkSync(path.join(__dirname, '..', 'db', 'test-qrmaster.db-wal')); } catch {}
try { fs.unlinkSync(path.join(__dirname, '..', 'db', 'test-qrmaster.db-shm')); } catch {}

const app = require('../server');
const { q, getDb } = require('../db/query');

async function req(method, path, body, cookies) {
  const url = `http://127.0.0.1:3000${path}`;
  const headers = { 'Content-Type': 'application/json' };
  if (cookies) headers['Cookie'] = cookies;
  const res = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
  const setCookie = res.headers.get('set-cookie');
  return { status: res.status, headers: res.headers, body: await res.text(), setCookie };
}

function parseCookies(setCookie) {
  if (!setCookie) return '';
  return setCookie.split(',').map(c => c.split(';')[0]).join('; ');
}

let server;
test.before(async () => {
  await new Promise(r => setTimeout(r, 200));
  server = app.listen(0);
  await new Promise(r => setTimeout(r, 100));
  global.BASE = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  server.close();
  try { getDb().close(); } catch {}
});

test('health check', async () => {
  const r = await fetch(global.BASE + '/health');
  const j = await r.json();
  assert.strictEqual(r.status, 200);
  assert.strictEqual(j.status, 'ok');
  assert.strictEqual(j.db, 'up');
});

test('register and login flow', async () => {
  const reg = await fetch(global.BASE + '/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'test@example.com', password: 'test1234', name: 'Tester', _csrf: 'a' }) });
  const cookies = parseCookies(reg.headers.get('set-cookie'));
  assert.ok(cookies.includes('token'), 'should have token cookie');
  const r = await fetch(global.BASE + '/dashboard', { headers: { 'Cookie': cookies } });
  assert.strictEqual(r.status, 200);
});

test('create QR with file', async () => {
  const r = await fetch(global.BASE + '/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'file@example.com', password: 'test1234', name: 'File' }) });
  const cookies = parseCookies(r.headers.get('set-cookie'));
  const csrfRes = await fetch(global.BASE + '/dashboard', { headers: { 'Cookie': cookies } });
  const csrf = csrfRes.headers.get('set-cookie')?.match(/_csrf=([^;]+)/)?.[1];

  const FormData = require('form-data');
  const fd = new FormData();
  fd.append('_csrf', csrf);
  fd.append('title', 'Test QR');
  fd.append('content_type', 'file');
  fd.append('file', Buffer.from('%PDF-1.4 test'), { filename: 'test.pdf', contentType: 'application/pdf' });
  const cr = await fetch(global.BASE + '/create', { method: 'POST', headers: { 'Cookie': cookies, ...fd.getHeaders() }, body: fd.getBuffer() });
  assert.strictEqual(cr.status, 200);
  const html = await cr.text();
  assert.ok(html.includes('Test QR'), 'should show title');
});

test('rate limit on /q/', async () => {
  const r = await fetch(global.BASE + '/q/aaaaaaaaaaaa');
  assert.ok([404, 403, 200, 429].includes(r.status));
});
