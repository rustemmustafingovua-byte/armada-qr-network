const path = require('path');
const fs = require('fs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

let db;

if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 10,
    idleTimeoutMillis: 30000,
  });
  db = {
    type: 'postgres',
    pool,
    prepare(sql) {
      let i = 0;
      const converted = sql.replace(/\?/g, () => `$${++i}`);
      return {
        run: (...params) => pool.query(converted, params).then(r => ({ changes: r.rowCount })),
        get: (...params) => pool.query(converted, params).then(r => r.rows[0] || null),
        all: (...params) => pool.query(converted, params).then(r => r.rows),
      };
    },
    exec: (sql) => pool.query(sql),
    close: () => pool.end(),
  };
} else {
  const Database = require('better-sqlite3');
  const dbDir = path.resolve(__dirname, '..', path.dirname(process.env.DB_PATH || './db/qrmaster.db'));
  const dbPath = path.resolve(__dirname, '..', process.env.DB_PATH || './db/qrmaster.db');
  if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
  const sdb = new Database(dbPath);
  sdb.pragma('journal_mode = WAL');
  sdb.pragma('foreign_keys = ON');
  sdb.pragma('busy_timeout = 5000');
  db = {
    type: 'sqlite',
    raw: sdb,
    prepare(sql) {
      const stmt = sdb.prepare(sql);
      return {
        run: (...params) => stmt.run(...params),
        get: (...params) => stmt.get(...params),
        all: (...params) => stmt.all(...params),
      };
    },
    exec: (sql) => sdb.exec(sql),
    close: () => sdb.close(),
  };
}

async function initialize() {
  if (db.type === 'postgres') {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS qr_codes (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL DEFAULT '',
        type TEXT NOT NULL DEFAULT 'dynamic',
        content_type TEXT NOT NULL DEFAULT 'link',
        target_url TEXT DEFAULT '',
        file_path TEXT DEFAULT '',
        file_name TEXT DEFAULT '',
        vcard_data TEXT DEFAULT '',
        text_data TEXT DEFAULT '',
        password_hash TEXT DEFAULT '',
        expires_at TIMESTAMP DEFAULT NULL,
        scan_limit INTEGER DEFAULT NULL,
        scan_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        fg_color TEXT DEFAULT '#000000',
        bg_color TEXT DEFAULT '#FFFFFF',
        dot_style TEXT DEFAULT 'square',
        logo_path TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS analytics (
        id SERIAL PRIMARY KEY,
        qr_id TEXT NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        country TEXT DEFAULT '',
        city TEXT DEFAULT '',
        device_type TEXT DEFAULT '',
        os TEXT DEFAULT '',
        browser TEXT DEFAULT '',
        referer TEXT DEFAULT ''
      );
      CREATE INDEX IF NOT EXISTS idx_analytics_qr_id ON analytics(qr_id);
      CREATE INDEX IF NOT EXISTS idx_analytics_scanned_at ON analytics(scanned_at);
      CREATE INDEX IF NOT EXISTS idx_analytics_qr_scanned ON analytics(qr_id, scanned_at);
      CREATE INDEX IF NOT EXISTS idx_qr_codes_user_id ON qr_codes(user_id);
      CREATE INDEX IF NOT EXISTS idx_qr_codes_user_created ON qr_codes(user_id, created_at DESC);
    `);
  } else {
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS qr_codes (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL DEFAULT '',
        type TEXT NOT NULL DEFAULT 'dynamic' CHECK(type IN ('static', 'dynamic')),
        content_type TEXT NOT NULL DEFAULT 'link' CHECK(content_type IN ('link', 'file', 'vcard', 'text')),
        target_url TEXT DEFAULT '',
        file_path TEXT DEFAULT '',
        file_name TEXT DEFAULT '',
        vcard_data TEXT DEFAULT '',
        text_data TEXT DEFAULT '',
        password_hash TEXT DEFAULT '',
        expires_at DATETIME DEFAULT NULL,
        scan_limit INTEGER DEFAULT NULL,
        scan_count INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        fg_color TEXT DEFAULT '#000000',
        bg_color TEXT DEFAULT '#FFFFFF',
        dot_style TEXT DEFAULT 'square',
        logo_path TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        qr_id TEXT NOT NULL,
        scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT DEFAULT '',
        user_agent TEXT DEFAULT '',
        country TEXT DEFAULT '',
        city TEXT DEFAULT '',
        device_type TEXT DEFAULT '',
        os TEXT DEFAULT '',
        browser TEXT DEFAULT '',
        referer TEXT DEFAULT '',
        FOREIGN KEY (qr_id) REFERENCES qr_codes(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_analytics_qr_id ON analytics(qr_id);
      CREATE INDEX IF NOT EXISTS idx_analytics_scanned_at ON analytics(scanned_at);
      CREATE INDEX IF NOT EXISTS idx_analytics_qr_scanned ON analytics(qr_id, scanned_at);
      CREATE INDEX IF NOT EXISTS idx_qr_codes_user_id ON qr_codes(user_id);
      CREATE INDEX IF NOT EXISTS idx_qr_codes_user_created ON qr_codes(user_id, created_at DESC);
    `);
  }
}

async function ensureAdmin() {
  try {
    let adminCount;
    if (db.type === 'postgres') {
      const r = await db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get();
      adminCount = parseInt(r.count);
    } else {
      adminCount = db.prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin'").get().count;
    }
    if (adminCount === 0) {
      let userCount;
      if (db.type === 'postgres') {
        const r = await db.prepare('SELECT COUNT(*) as count FROM users').get();
        userCount = parseInt(r.count);
      } else {
        userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
      }
      if (userCount > 0) {
        const firstUser = db.type === 'postgres'
          ? await db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get()
          : db.prepare('SELECT id FROM users ORDER BY id ASC LIMIT 1').get();
        await db.prepare('UPDATE users SET role = ? WHERE id = ?').run('admin', firstUser.id);
        console.log(`  ✓ User "${firstUser.id}" promoted to admin`);
      } else {
        const bcrypt = require('bcryptjs');
        const hash = await bcrypt.hash('admin123', 12);
        await db.prepare('INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)').run('admin@armada.com', hash, 'Admin', 'admin');
        console.log('  ✓ Default admin created: admin@armada.com / admin123');
      }
    }
  } catch (e) {
    console.error('Admin check error:', e.message);
  }
}

module.exports = { db, initialize, ensureAdmin };
