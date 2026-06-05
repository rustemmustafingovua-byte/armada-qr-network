const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const helmet = require('helmet');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { initialize, ensureAdmin, migrateV2, getDb } = require('./db/schema');
const { getLocalIP } = require('./utils/network');
const { logEvent, requestLogger } = require('./utils/logger');
const authRoutes = require('./routes/auth');
const qrRoutes = require('./routes/qr');
const redirectRoutes = require('./routes/redirect');
const analyticsRoutes = require('./routes/analytics');
const adminRoutes = require('./routes/admin');
const messagesRoutes = require('./routes/messages');
const filesRoutes = require('./routes/files');
const apiRoutes = require('./routes/api');
const settingsRoutes = require('./routes/settings');

const app = express();
const PORT = parseInt(process.env.PORT, 10) || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

const REQUIRED_ENV = ['JWT_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be at least 32 characters');
  process.exit(1);
}

const uploadDir = path.resolve(__dirname, process.env.UPLOAD_DIR || './public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const start = Date.now();

app.disable('x-powered-by');
app.disable('etag');
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);
app.set('query parser', 'simple');

const cspDirectives = {
  defaultSrc: ["'self'"],
  scriptSrc: [
    "'self'",
    "https://cdn.tailwindcss.com",
    "https://cdn.jsdelivr.net",
    (req, res) => `'nonce-${res.locals.cspNonce}'`
  ],
  styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
  imgSrc: ["'self'", "data:", "blob:", "https:"],
  connectSrc: ["'self'", "blob:"],
  fontSrc: ["'self'", "data:"],
  objectSrc: ["'none'"],
  mediaSrc: ["'self'", "blob:"],
  frameSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"],
  frameAncestors: ["'none'"],
  upgradeInsecureRequests: IS_PROD ? [] : null
};

app.use((req, res, next) => {
  res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: cspDirectives
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  hidePoweredBy: true
}));

app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});

app.use(compression({
  level: 6,
  threshold: 256,
  filter: (req, res) => {
    if (req.path.startsWith('/q/') || req.path.startsWith('/download/') || req.path.startsWith('/d/')) return false;
    if (res.getHeader('Content-Type')?.includes('image/')) return false;
    return compression.filter(req, res);
  }
}));

app.use(requestLogger);

const postOnly = (limiter) => (req, res, next) => (req.method === 'POST' ? limiter(req, res, next) : next());

const authLimiter = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many login attempts' },
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip
});
app.use('/login', postOnly(authLimiter));
app.use('/register', postOnly(authLimiter));

const scanLimiter = require('express-rate-limit')({
  windowMs: 1000, max: parseInt(process.env.MAX_SCAN_RATE || '15', 10),
  message: { error: 'Too many requests' },
  keyGenerator: (req) => req.ip,
  skip: (req) => req.path === '/q/' || req.path === '/q'
});
app.use('/q/', scanLimiter);

const apiLimiter = require('express-rate-limit')({
  windowMs: 60 * 1000, max: 240,
  message: { error: 'Too many API requests' },
  keyGenerator: (req) => req.ip,
  skip: (req) => req.path.includes('/api/messages/') && req.method === 'GET'
});
app.use('/api/', apiLimiter);

const uploadLimiter = require('express-rate-limit')({
  windowMs: 60 * 1000, max: 10,
  message: { error: 'Too many uploads' },
  keyGenerator: (req) => req.ip
});
app.use('/create', postOnly(uploadLimiter));

app.use(express.urlencoded({ extended: false, limit: '500kb' }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

app.use('/static', express.static(path.join(__dirname, 'public'), {
  maxAge: IS_PROD ? '7d' : 0,
  etag: true, lastModified: true,
  setHeaders: (res, p) => {
    if (p.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

app.use((req, res, next) => {
  let token = req.cookies?._csrf;
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    res.cookie('_csrf', token, {
      httpOnly: false, secure: IS_PROD, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000, path: '/'
    });
  }
  res.locals._csrf = token;
  next();
});

const csrfCheck = (req, res, next) => {
  if (/^(GET|HEAD|OPTIONS)$/.test(req.method)) return next();
  if (req.path === '/login' || req.path === '/register') return next();
  if (req.path.startsWith('/api/') && req.headers['authorization']?.startsWith('Bearer ')) return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== req.cookies?._csrf) {
    return next(Object.assign(new Error('Invalid CSRF token'), { status: 403, csrf: true }));
  }
  next();
};
app.use((req, res, next) => {
  const publicPaths = ['/create', '/edit/', '/api/verify-code/', '/api/messages/', '/api/verify', '/webhook/'];
  if (publicPaths.some(p => req.path.startsWith(p))) return next();
  csrfCheck(req, res, next);
});

app.use((req, res, next) => {
  res.locals.lang = (req.cookies?.lang || 'en').toLowerCase().substring(0, 2);
  res.locals.user = null;
  res.locals.flash = null;
  res.locals.error = null;
  res.locals.success = null;
  if (req.cookies?.flash) {
    try {
      const f = JSON.parse(Buffer.from(req.cookies.flash, 'base64').toString('utf8'));
      res.locals.flash = f;
      if (f.type === 'success') res.locals.success = f.msg;
      if (f.type === 'error') res.locals.error = f.msg;
      res.clearCookie('flash', { path: '/' });
    } catch {}
  }
  next();
});

app.locals.flash = function(res, type, msg) {
  const v = JSON.stringify({ type, msg });
  res.cookie('flash', Buffer.from(v).toString('base64'), { path: '/', maxAge: 30_000, httpOnly: true, sameSite: 'lax' });
};

app.use('/', authRoutes);
app.use('/', qrRoutes);
app.use('/', filesRoutes);
app.use('/', redirectRoutes);
app.use('/', analyticsRoutes);
app.use('/', adminRoutes);
app.use('/', messagesRoutes);
app.use('/', apiRoutes);
app.use('/', settingsRoutes);

app.get('/', (req, res) => res.redirect(302, '/dashboard'));
app.get('/lang/:lang', (req, res) => {
  const lang = ['en', 'ru'].includes(req.params.lang) ? req.params.lang : 'en';
  res.cookie('lang', lang, { maxAge: 365 * 24 * 60 * 60 * 1000, path: '/' });
  res.redirect('back' || '/dashboard');
});
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /'));
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.get('/ping', (req, res) => res.set('Cache-Control', 'no-cache').send('pong'));
app.get('/health', async (req, res) => {
  const dbState = getDb();
  let dbOk = false;
  try { await dbState.prepare('SELECT 1 as ok').get(); dbOk = true; } catch {}
  const mem = process.memoryUsage();
  const uptime = Math.floor(process.uptime());
  const status = dbOk ? 200 : 503;
  res.status(status).json({
    status: dbOk ? 'ok' : 'degraded',
    db: dbOk ? 'up' : 'down',
    dbType: dbState.type,
    uptime,
    memory: { rss: mem.rss, heap: mem.heapUsed },
    pid: process.pid,
    version: process.env.npm_package_version || '1.0.0',
    startedAt: new Date(start).toISOString()
  });
});

app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.status(404).render('public-error', { message: 'Page not found', code: 404 });
});

app.use((err, req, res, next) => {
  const status = err.status || 500;
  if (err.csrf) return res.status(403).render('public-error', { message: 'Session expired, please refresh and try again', code: 403 });
  if (err.type === 'entity.too.large') return res.status(413).render('public-error', { message: 'Request too large', code: 413 });
  if (err.type === 'entity.parse.failed') return res.status(400).render('public-error', { message: 'Invalid request', code: 400 });
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).render('public-error', { message: 'File too large (max 200 MB)', code: 413 });
  logEvent('error', 'unhandled', { reqId: req.id, path: req.path, msg: err.message, stack: IS_PROD ? undefined : err.stack });
  if (req.xhr || req.path.startsWith('/api/') || req.accepts('json') === 'json') {
    return res.status(status).json({ error: err.message || 'Internal error', reqId: req.id });
  }
  res.status(status).render('public-error', { message: status === 404 ? 'Not found' : 'Server error', code: status, reqId: req.id });
});

(async () => {
  try { await initialize(); } catch (e) { logEvent('error', 'init_failed', { msg: e.message }); }
  try { await migrateV2(); } catch (e) { logEvent('error', 'migrate_failed', { msg: e.message }); }
  try { await ensureAdmin(); } catch (e) { logEvent('error', 'admin_failed', { msg: e.message }); }
  logEvent('info', 'ready', { db: process.env.DATABASE_URL ? 'postgres' : 'sqlite' });
})();

const server = app.listen(PORT, '0.0.0.0', () => {
  const localIP = getLocalIP();
  logEvent('info', 'started', {
    port: PORT, env: IS_PROD ? 'production' : 'development',
    db: process.env.DATABASE_URL ? 'postgres' : 'sqlite',
    local: `http://localhost:${PORT}`,
    network: `http://${localIP}:${PORT}`,
    public: process.env.PUBLIC_URL || null
  });
  console.log(`\n  Armada QR Network — running on :${PORT}  (${IS_PROD ? 'PROD' : 'DEV'})\n`);
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logEvent('info', 'shutdown_initiated', { signal });
  server.close(() => logEvent('info', 'http_closed'));
  const forceKill = setTimeout(() => {
    logEvent('error', 'shutdown_timeout_force_exit');
    process.exit(1);
  }, 10_000);
  forceKill.unref();
  try {
    const dbState = getDb();
    if (dbState?.close) dbState.close();
  } catch (e) { logEvent('error', 'db_close_error', { msg: e.message }); }
  setTimeout(() => process.exit(0), 200);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  logEvent('error', 'uncaught_exception', { msg: err.message, stack: err.stack });
});
process.on('unhandledRejection', (reason) => {
  logEvent('error', 'unhandled_rejection', { msg: String(reason) });
});

module.exports = app;
