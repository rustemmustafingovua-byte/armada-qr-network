const { db } = require('./adapter');

const q = {
  async get(sql, params = []) {
    return db.prepare(sql).get(...params);
  },
  async all(sql, params = []) {
    return db.prepare(sql).all(...params);
  },
  async run(sql, params = []) {
    return db.prepare(sql).run(...params);
  },
};

const asyncWrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { q, asyncWrap, db };
