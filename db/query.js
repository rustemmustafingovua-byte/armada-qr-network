const { db } = require('./adapter');

function fixSQL(sql) {
  if (db.type !== 'postgres') return sql;
  return sql
    .replace(/DATE\('now',\s*'(-?\d+)\s+(\w+)'\)/g, "CURRENT_TIMESTAMP - INTERVAL '$1 $2'")
    .replace(/DATE\('now'\)/g, 'CURRENT_DATE')
    .replace(/scanned_at >= DATE\('now'\)/g, "scanned_at >= CURRENT_DATE");
}

const q = {
  async get(sql, params = []) {
    return db.prepare(fixSQL(sql)).get(...params);
  },
  async all(sql, params = []) {
    return db.prepare(fixSQL(sql)).all(...params);
  },
  async run(sql, params = []) {
    return db.prepare(fixSQL(sql)).run(...params);
  },
};

const asyncWrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { q, asyncWrap, db, fixSQL };
