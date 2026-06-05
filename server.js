const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const { initialize, ensureAdmin } = require('./db/schema');
const { getLocalIP, getNgrokUrl } = require('./utils/network');
const authRoutes = require('./routes/auth');
const qrRoutes = require('./routes/qr');
const redirectRoutes = require('./routes/redirect');
const analyticsRoutes = require('./routes/analytics');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Environment validation ──
const REQUIRED_ENV = ['JWT_SECRET'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ── Directories ──
const uploadDir = path.resolve(__dirname, process.env.UPLOAD_DIR || './public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

// ── Startup ──
(async () => {
  await initialize();
  await ensureAdmin();
})();

// ── Settings ──
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);
app.set('x-powered-by', false);
app.set('query parser', 'simple');
app.set('subdomain offset', 2);
app.enable('etag');

// ── Security headers ──
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// ── Compression ──
app.use(compression({ level: 6, threshold: 128, filter: (req, res) => {
  if (req.path.startsWith('/q/') || req.path.startsWith('/download/')) return false;
  return compression.filter(req, res);
}}));

// ── Request logging ──
app.use(morgan(process.env.NODE_ENV === 'production'
  ? ':remote-addr :method :url :status :res[content-length] - :response-time ms'
  : 'dev'
));

// ── Rate limiters ──
function postOnly(limiter) {
  return (req, res, next) => req.method === 'POST' ? limiter(req, res, next) : next();
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many login attempts' },
  standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => req.ip
});
app.use('/login', postOnly(authLimiter));
app.use('/register', postOnly(authLimiter));

const scanLimiter = rateLimit({
  windowMs: 1000, max: parseInt(process.env.MAX_SCAN_RATE || '10'),
  message: { error: 'Too many requests' },
  keyGenerator: (req) => req.ip
});
app.use('/q/', scanLimiter);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  message: { error: 'Too many API requests' },
  keyGenerator: (req) => req.ip
});
app.use('/api/', apiLimiter);

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000, max: 10,
  message: { error: 'Too many uploads' },
  keyGenerator: (req) => req.ip
});
app.use('/create', postOnly(uploadLimiter));

// ── Body parsing ──
app.use(express.urlencoded({ extended: false, limit: '500kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// ── Static files ──
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '7d', etag: true, lastModified: true, immutable: true
}));

// ── CSRF ──
app.use((req, res, next) => {
  let token = req.cookies?._csrf;
  if (!token) {
    token = crypto.randomBytes(32).toString('hex');
    res.cookie('_csrf', token, {
      httpOnly: false, secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000
    });
  }
  res.locals._csrf = token;
  next();
});

app.use((req, res, next) => {
  if (/^(GET|HEAD|OPTIONS)$/.test(req.method)) return next();
  if (req.path === '/login' || req.path === '/register') return next();
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== req.cookies?._csrf) {
    const e = new Error('Invalid CSRF token');
    e.status = 403; e.csrf = true;
    return next(e);
  }
  next();
});

// ── Routes ──
app.use('/', authRoutes);
app.use('/', qrRoutes);
app.use('/', redirectRoutes);
app.use('/', analyticsRoutes);
app.use('/', adminRoutes);

app.get('/', (req, res) => res.redirect(302, '/dashboard'));
app.get('/robots.txt', (req, res) => res.type('text/plain').send('User-agent: *\nDisallow: /'));
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.get('/ping', (req, res) => res.set('Cache-Control', 'no-cache').send('pong'));
app.get('/api/server-info', (req, res) => {
  const start = process.hrtime.bigint();
  res.json({
    localUrl: `http://localhost:${PORT}`,
    networkUrl: `http://${getLocalIP()}:${PORT}`,
    publicUrl: process.env.PUBLIC_URL || null,
    port: PORT, status: 'running'
  });
});

// ── 404 ──
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  res.status(404).render('public-error', { message: 'Page not found', code: 404 });
});

// ── Error handler ──
app.use((err, req, res, next) => {
  if (err.csrf) return res.status(403).render('public-error', { message: 'Session expired, please refresh and try again', code: 403 });
  if (err.type === 'entity.too.large') return res.status(413).render('public-error', { message: 'Request too large', code: 413 });
  if (err.type === 'entity.parse.failed') return res.status(400).render('public-error', { message: 'Invalid request', code: 400 });
  console.error('Error:', err.message);
  if (req.xhr || req.path.startsWith('/api/')) return res.status(err.status || 500).json({ error: err.message || 'Internal error' });
  res.status(err.status || 500).render('public-error', { message: err.status === 404 ? 'Not found' : 'Server error', code: err.status || 500 });
});

// ── Start ──
const localIP = getLocalIP();
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n  ╔══════════════════════════════╗`);
  console.log(`  ║   Armada QR Network          ║`);
  console.log(`  ╚══════════════════════════════╝\n`);
  console.log(`  Local:    http://localhost:${PORT}`);
  console.log(`  Network:  http://${localIP}:${PORT}`);
  console.log(`  DB:       ${process.env.DATABASE_URL ? 'PostgreSQL' : 'SQLite'}`);
  console.log(`  Cache:    QR image + static\n`);
});
