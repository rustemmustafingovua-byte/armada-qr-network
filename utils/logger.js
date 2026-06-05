const isProd = process.env.NODE_ENV === 'production';

function fmt(level, event, meta = {}) {
  const entry = { ts: new Date().toISOString(), level, event, ...meta };
  return isProd ? JSON.stringify(entry) : `[${entry.ts}] ${level.toUpperCase()} ${event} ${JSON.stringify(meta)}`;
}

function logEvent(level, event, meta) {
  const line = fmt(level, event, meta);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

function requestLogger(req, res, next) {
  const start = process.hrtime.bigint();
  const reqId = req.headers['x-request-id'] || require('crypto').randomBytes(8).toString('hex');
  req.id = reqId;
  res.setHeader('X-Request-Id', reqId);
  res.on('finish', () => {
    const dur = Number(process.hrtime.bigint() - start) / 1e6;
    logEvent('info', 'http', {
      reqId, method: req.method, path: req.path,
      status: res.statusCode,
      ms: Math.round(dur * 100) / 100,
      ip: req.ip,
      ua: (req.get('User-Agent') || '').substring(0, 120)
    });
  });
  next();
}

async function audit(userId, event, details = {}) {
  try {
    const { q } = require('../db/query');
    await q.run(
      'INSERT INTO audit_log (user_id, event, details, ip, user_agent) VALUES (?, ?, ?, ?, ?)',
      [userId || null, event, JSON.stringify(details).substring(0, 4000), details._ip || '', details._ua || '']
    );
  } catch (e) {
    logEvent('error', 'audit_write_failed', { msg: e.message, event });
  }
}

module.exports = { logEvent, requestLogger, audit };
