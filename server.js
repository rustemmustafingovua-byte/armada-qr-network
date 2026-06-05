const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const compression = require('compression');
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

const uploadDir = path.resolve(__dirname, process.env.UPLOAD_DIR || './public/uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

(async () => {
  await initialize();
  await ensureAdmin();
})();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('trust proxy', 1);
app.set('x-powered-by', false);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net"],
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

app.use(compression({ level: 6, threshold: 256 }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many login attempts, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip
});
app.use('/login', authLimiter);
app.use('/register', authLimiter);

const scanLimiter = rateLimit({
  windowMs: 1000,
  max: parseInt(process.env.MAX_SCAN_RATE || '10'),
  message: { error: 'Too many requests, slow down' },
  keyGenerator: (req) => req.ip
});
app.use('/q/', scanLimiter);

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: 'Too many API requests' },
  keyGenerator: (req) => req.ip
});
app.use('/api/', apiLimiter);

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many uploads, try later' },
  keyGenerator: (req) => req.ip
});
app.use('/create', uploadLimiter);

app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '7d',
  etag: true,
  lastModified: true
}));

const crypto = require('crypto');
app.use((req, res, next) => {
  if (!req.cookies?._csrf) {
    res.cookie('_csrf', crypto.randomBytes(32).toString('hex'), { httpOnly: false, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 });
  }
  res.locals._csrf = req.cookies?._csrf || '';
  next();
});

app.use((req, res, next) => {
  if (!/^(GET|HEAD|OPTIONS)$/.test(req.method)) {
    const token = req.headers['x-csrf-token'] || req.body?._csrf;
    if (!token || token !== req.cookies?._csrf) {
      if (req.xhr || req.path.startsWith('/api/')) return res.status(403).json({ error: 'Invalid CSRF token' });
      return res.status(403).render('public-error', { message: 'Invalid session', code: 403 });
    }
  }
  next();
});

app.use('/', authRoutes);
app.use('/', qrRoutes);
app.use('/', redirectRoutes);
app.use('/', analyticsRoutes);
app.use('/', adminRoutes);

app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/ping', (req, res) => res.send('pong'));

app.get('/api/server-info', (req, res) => {
  res.json({
    localUrl: `http://localhost:${PORT}`,
    networkUrl: `http://${getLocalIP()}:${PORT}`,
    publicUrl: process.env.PUBLIC_URL || null,
    port: PORT,
    status: 'running'
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (req.xhr || req.path.startsWith('/api/')) {
    return res.status(500).json({ error: 'Internal server error' });
  }
  res.status(500).render('public-error', { message: 'Server error', code: 500 });
});

const localIP = getLocalIP();
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`\n  ╔══════════════════════════════════╗`);
  console.log(`  ║   Armada QR Network              ║`);
  console.log(`  ╚══════════════════════════════════╝\n`);
  console.log(`  Local:    http://localhost:${PORT}`);
  console.log(`  Network:  http://${localIP}:${PORT}`);
  const ngrokUrl = await getNgrokUrl();
  if (ngrokUrl) console.log(`  Public:   ${ngrokUrl}`);
  console.log(`  DB:       ${process.env.DATABASE_URL ? 'PostgreSQL' : 'SQLite'}`);
  console.log(`  Security: helmet + rate-limiting + CSP`);
  console.log(`  For public access: bash deploy.sh tunnel\n`);
});
