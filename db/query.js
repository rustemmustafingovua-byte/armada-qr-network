const { db, getDb } = require('./adapter');
const { logEvent } = require('../utils/logger');

function fixSQL(sql) {
  if (db.type !== 'postgres') return sql;
  let out = sql;
  out = out
    .replace(/DATE\('now',\s*'(-?\d+)\s+(\w+)'\)/g, "CURRENT_TIMESTAMP - INTERVAL '$1 $2'")
    .replace(/DATE\('now'\)/g, 'CURRENT_DATE')
    .replace(/scanned_at >= DATE\('now'\)/g, 'scanned_at >= CURRENT_DATE')
    .replace(/last_insert_rowid\(\)/g, 'lastval()');
  let idx = 0;
  out = out.replace(/\?/g, () => { idx += 1; return '$' + idx; });
  return out;
}

const q = {
  async get(sql, params = []) { return db.prepare(fixSQL(sql)).get(...params); },
  async all(sql, params = []) { return db.prepare(fixSQL(sql)).all(...params); },
  async run(sql, params = []) { return db.prepare(fixSQL(sql)).run(...params); },
  async transaction(fn) { return db.transaction(fn); },
};

const asyncWrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch((err) => {
  logEvent('error', 'route_error', { path: req.path, msg: err.message });
  next(err);
});

module.exports = { q, asyncWrap, db, getDb, fixSQL };
