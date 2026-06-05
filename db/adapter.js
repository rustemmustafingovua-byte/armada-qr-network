const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

let db;
let stmtCache = new Map();

function fixSQL(sql) {
  if (db.type !== 'postgres') return sql;
  return sql
    .replace(/DATE\('now',\s*'(-?\d+)\s+(\w+)'\)/g, "CURRENT_TIMESTAMP - INTERVAL '$1 $2'")
    .replace(/DATE\('now'\)/g, 'CURRENT_DATE')
    .replace(/scanned_at >= DATE\('now'\)/g, 'scanned_at >= CURRENT_DATE')
    .replace(/last_insert_rowid\(\)/g, 'lastval()');
}

if (process.env.DATABASE_URL) {
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
  pool.on('error', (err) => console.error('PG pool error:', err.message));
  db = {
    type: 'postgres',
    pool,
    prepare(sql) {
      const converted = fixSQL(sql);
      return {
        run: (...params) => pool.query(converted, params).then(r => ({ changes: r.rowCount, lastInsertRowid: r.rows?.[0]?.id })),
        get: (...params) => pool.query(converted, params).then(r => r.rows[0] || null),
        all: (...params) => pool.query(converted, params).then(r => r.rows),
      };
    },
    exec: (sql) => pool.query(sql),
    close: () => pool.end(),
    transaction: async (fn) => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const txDb = {
          type: 'postgres',
          prepare(sql) {
            const converted = fixSQL(sql);
            return {
              run: (...params) => client.query(converted, params).then(r => ({ changes: r.rowCount, lastInsertRowid: r.rows?.[0]?.id })),
              get: (...params) => client.query(converted, params).then(r => r.rows[0] || null),
              all: (...params) => client.query(converted, params).then(r => r.rows),
            };
          },
        };
        const result = await fn(txDb);
        await client.query('COMMIT');
        return result;
      } catch (e) {
        await client.query('ROLLBACK');
        throw e;
      } finally {
        client.release();
      }
    },
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
  sdb.pragma('synchronous = NORMAL');
  sdb.pragma('temp_store = MEMORY');
  sdb.pragma('cache_size = -64000');
  const getStmt = (sql) => {
    if (stmtCache.has(sql)) return stmtCache.get(sql);
    try {
      const stmt = sdb.prepare(fixSQL(sql));
      stmtCache.set(sql, stmt);
      return stmt;
    } catch (e) {
      console.error('  [getStmt] PREPARE FAILED:', e.message, 'SQL:', sql.substring(0, 200));
      throw e;
    }
  };
  db = {
    type: 'sqlite',
    raw: sdb,
    prepare(sql) {
      const stmt = getStmt(sql);
      return {
        run: (...params) => stmt.run(...params),
        get: (...params) => stmt.get(...params),
        all: (...params) => stmt.all(...params),
      };
    },
    exec: (sql) => sdb.exec(sql),
    close: () => { stmtCache.clear(); sdb.close(); },
    transaction: async (fn) => sdb.transaction(fn)({ type: 'sqlite', prepare: (s) => ({ run: (...p) => getStmt(s).run(...p), get: (...p) => getStmt(s).get(...p), all: (...p) => getStmt(s).all(...p) }) }),
  };
}

function getDb() { return db; }

const SCHEMA_SQLITE = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    totp_secret TEXT DEFAULT '',
    totp_enabled INTEGER DEFAULT 0,
    language TEXT DEFAULT 'en',
    email_notifications INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS qr_codes (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'dynamic' CHECK(type IN ('static', 'dynamic')),
    content_type TEXT NOT NULL DEFAULT 'link' CHECK(content_type IN ('link', 'file', 'vcard', 'text', 'wifi', 'event')),
    target_url TEXT DEFAULT '',
    file_path TEXT DEFAULT '',
    file_name TEXT DEFAULT '',
    vcard_data TEXT DEFAULT '',
    text_data TEXT DEFAULT '',
    wifi_ssid TEXT DEFAULT '',
    wifi_password TEXT DEFAULT '',
    wifi_encryption TEXT DEFAULT 'WPA',
    wifi_hidden INTEGER DEFAULT 0,
    event_title TEXT DEFAULT '',
    event_location TEXT DEFAULT '',
    event_start DATETIME DEFAULT NULL,
    event_end DATETIME DEFAULT NULL,
    event_description TEXT DEFAULT '',
    password_hash TEXT DEFAULT '',
    verify_code_hash TEXT DEFAULT '',
    expires_at DATETIME DEFAULT NULL,
    scan_limit INTEGER DEFAULT NULL,
    scan_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    fg_color TEXT DEFAULT '#000000',
    bg_color TEXT DEFAULT '#FFFFFF',
    dot_style TEXT DEFAULT 'square',
    logo_path TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    webhook_url TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    notes TEXT DEFAULT '',
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
    region TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    os TEXT DEFAULT '',
    browser TEXT DEFAULT '',
    referer TEXT DEFAULT '',
    unique_hash TEXT DEFAULT '',
    FOREIGN KEY (qr_id) REFERENCES qr_codes(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_analytics_qr_id ON analytics(qr_id);
  CREATE INDEX IF NOT EXISTS idx_analytics_scanned_at ON analytics(scanned_at);
  CREATE INDEX IF NOT EXISTS idx_analytics_qr_scanned ON analytics(qr_id, scanned_at);
  CREATE INDEX IF NOT EXISTS idx_qr_codes_user_id ON qr_codes(user_id);
  CREATE INDEX IF NOT EXISTS idx_qr_codes_user_created ON qr_codes(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS file_uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    qr_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT DEFAULT 'application/octet-stream',
    original_size INTEGER DEFAULT 0,
    compressed_size INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (qr_id) REFERENCES qr_codes(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS qr_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    qr_id TEXT NOT NULL,
    sender_name TEXT NOT NULL DEFAULT '',
    sender_ip TEXT DEFAULT '',
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    reply TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (qr_id) REFERENCES qr_codes(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_messages_qr_id ON qr_messages(qr_id);
  CREATE INDEX IF NOT EXISTS idx_messages_read ON qr_messages(qr_id, is_read);
  CREATE INDEX IF NOT EXISTS idx_file_uploads_qr_id ON file_uploads(qr_id);
  CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    last_used_at DATETIME DEFAULT NULL,
    expires_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    qr_id TEXT NOT NULL,
    event TEXT NOT NULL,
    url TEXT NOT NULL,
    payload TEXT NOT NULL,
    response_status INTEGER DEFAULT 0,
    response_body TEXT DEFAULT '',
    attempt INTEGER DEFAULT 1,
    succeeded INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_webhook_user ON webhook_deliveries(user_id);
  CREATE INDEX IF NOT EXISTS idx_webhook_qr ON webhook_deliveries(qr_id);
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER DEFAULT NULL,
    event TEXT NOT NULL,
    details TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`;

const SCHEMA_POSTGRES = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT 'user',
    totp_secret TEXT DEFAULT '',
    totp_enabled INTEGER DEFAULT 0,
    language TEXT DEFAULT 'en',
    email_notifications INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    wifi_ssid TEXT DEFAULT '',
    wifi_password TEXT DEFAULT '',
    wifi_encryption TEXT DEFAULT 'WPA',
    wifi_hidden INTEGER DEFAULT 0,
    event_title TEXT DEFAULT '',
    event_location TEXT DEFAULT '',
    event_start TIMESTAMP DEFAULT NULL,
    event_end TIMESTAMP DEFAULT NULL,
    event_description TEXT DEFAULT '',
    password_hash TEXT DEFAULT '',
    verify_code_hash TEXT DEFAULT '',
    expires_at TIMESTAMP DEFAULT NULL,
    scan_limit INTEGER DEFAULT NULL,
    scan_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    fg_color TEXT DEFAULT '#000000',
    bg_color TEXT DEFAULT '#FFFFFF',
    dot_style TEXT DEFAULT 'square',
    logo_path TEXT DEFAULT '',
    file_size INTEGER DEFAULT 0,
    webhook_url TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    notes TEXT DEFAULT '',
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
    region TEXT DEFAULT '',
    device_type TEXT DEFAULT '',
    os TEXT DEFAULT '',
    browser TEXT DEFAULT '',
    referer TEXT DEFAULT '',
    unique_hash TEXT DEFAULT ''
  );
  CREATE INDEX IF NOT EXISTS idx_analytics_qr_id ON analytics(qr_id);
  CREATE INDEX IF NOT EXISTS idx_analytics_scanned_at ON analytics(scanned_at);
  CREATE INDEX IF NOT EXISTS idx_analytics_qr_scanned ON analytics(qr_id, scanned_at);
  CREATE INDEX IF NOT EXISTS idx_analytics_unique ON analytics(qr_id, unique_hash);
  CREATE INDEX IF NOT EXISTS idx_qr_codes_user_id ON qr_codes(user_id);
  CREATE INDEX IF NOT EXISTS idx_qr_codes_user_created ON qr_codes(user_id, created_at DESC);
  CREATE TABLE IF NOT EXISTS file_uploads (
    id SERIAL PRIMARY KEY,
    qr_id TEXT NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    original_name TEXT NOT NULL,
    mime_type TEXT DEFAULT 'application/octet-stream',
    original_size INTEGER DEFAULT 0,
    compressed_size INTEGER DEFAULT 0,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS qr_messages (
    id SERIAL PRIMARY KEY,
    qr_id TEXT NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
    sender_name TEXT NOT NULL DEFAULT '',
    sender_ip TEXT DEFAULT '',
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    reply TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_messages_qr_id ON qr_messages(qr_id);
  CREATE INDEX IF NOT EXISTS idx_messages_read ON qr_messages(qr_id, is_read);
  CREATE INDEX IF NOT EXISTS idx_file_uploads_qr_id ON file_uploads(qr_id);
  CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    last_used_at TIMESTAMP DEFAULT NULL,
    expires_at TIMESTAMP DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    qr_id TEXT NOT NULL,
    event TEXT NOT NULL,
    url TEXT NOT NULL,
    payload TEXT NOT NULL,
    response_status INTEGER DEFAULT 0,
    response_body TEXT DEFAULT '',
    attempt INTEGER DEFAULT 1,
    succeeded INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_webhook_user ON webhook_deliveries(user_id);
  CREATE INDEX IF NOT EXISTS idx_webhook_qr ON webhook_deliveries(qr_id);
  CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER DEFAULT NULL,
    event TEXT NOT NULL,
    details TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`;

async function initialize() {
  try {
    if (db.type === 'postgres') await db.exec(SCHEMA_POSTGRES);
    else db.exec(SCHEMA_SQLITE);
  } catch (e) {
    console.error('Schema init error:', e.message);
    if (db.type === 'sqlite') {
      try {
        const statements = SCHEMA_SQLITE.split(/;\s*\n/).map(s => s.trim()).filter(s => s && !/^CREATE INDEX/i.test(s));
        for (const s of statements) {
          try { db.exec(s); } catch {}
        }
      } catch {}
    } else {
      throw e;
    }
  }
}

async function migrateV2() {
  const migrations = db.type === 'postgres' ? [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS language TEXT DEFAULT 'en'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_notifications INTEGER DEFAULT 1",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS verify_code_hash TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS file_size INTEGER DEFAULT 0",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS wifi_ssid TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS wifi_password TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS wifi_encryption TEXT DEFAULT 'WPA'",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS wifi_hidden INTEGER DEFAULT 0",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS event_title TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS event_location TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS event_start TIMESTAMP DEFAULT NULL",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS event_end TIMESTAMP DEFAULT NULL",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS event_description TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS webhook_url TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS tags TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT ''",
    "ALTER TABLE file_uploads ADD COLUMN IF NOT EXISTS download_count INTEGER DEFAULT 0",
    "ALTER TABLE analytics ADD COLUMN IF NOT EXISTS region TEXT DEFAULT ''",
    "ALTER TABLE analytics ADD COLUMN IF NOT EXISTS unique_hash TEXT DEFAULT ''",
  ] : [
    "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'",
    "ALTER TABLE users ADD COLUMN email_notifications INTEGER DEFAULT 1",
    "ALTER TABLE qr_codes ADD COLUMN verify_code_hash TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN file_size INTEGER DEFAULT 0",
    "ALTER TABLE qr_codes ADD COLUMN wifi_ssid TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN wifi_password TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN wifi_encryption TEXT DEFAULT 'WPA'",
    "ALTER TABLE qr_codes ADD COLUMN wifi_hidden INTEGER DEFAULT 0",
    "ALTER TABLE qr_codes ADD COLUMN event_title TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN event_location TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN event_start DATETIME DEFAULT NULL",
    "ALTER TABLE qr_codes ADD COLUMN event_end DATETIME DEFAULT NULL",
    "ALTER TABLE qr_codes ADD COLUMN event_description TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN webhook_url TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN tags TEXT DEFAULT ''",
    "ALTER TABLE qr_codes ADD COLUMN notes TEXT DEFAULT ''",
    "ALTER TABLE file_uploads ADD COLUMN download_count INTEGER DEFAULT 0",
    "ALTER TABLE analytics ADD COLUMN region TEXT DEFAULT ''",
    "ALTER TABLE analytics ADD COLUMN unique_hash TEXT DEFAULT ''",
    "CREATE INDEX IF NOT EXISTS idx_analytics_unique ON analytics(qr_id, unique_hash)",
    "CREATE INDEX IF NOT EXISTS idx_qr_codes_tags ON qr_codes(tags)",
  ];
  for (const m of migrations) {
    try { db.type === 'postgres' ? await db.exec(m) : db.exec(m); } catch {}
  }

  if (db.type === 'sqlite') {
    try {
      const cs = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='qr_codes'").get();
      if (cs && cs.sql && /content_type IN \(/.test(cs.sql)) {
        console.log('  → Migrating qr_codes to drop old CHECK constraint (allow wifi/event)…');
        const cols = db.raw.prepare("PRAGMA table_info(qr_codes)").all();
        const colNames = cols.map(c => c.name);
        const colList = colNames.map(c => `"${c}"`).join(', ');
        const placeholders = colNames.map(() => '?').join(', ');
        const tx = db.raw.transaction(() => {
          db.raw.pragma('foreign_keys = OFF');

          const fu = db.raw.prepare("SELECT sql FROM sqlite_master WHERE name='file_uploads'").get();
          const hasFu = !!fu;
          let fuRows = [];
          if (hasFu) {
            const fuCols = db.raw.prepare("PRAGMA table_info(file_uploads)").all();
            const fuColNames = fuCols.map(c => c.name);
            fuRows = db.raw.prepare(`SELECT ${fuColNames.map(c => `"${c}"`).join(', ')} FROM file_uploads`).all();
            db.raw.exec(`DROP TABLE file_uploads`);
          }

          const qm = db.raw.prepare("SELECT sql FROM sqlite_master WHERE name='qr_messages'").get();
          const hasQm = !!qm;
          let qmRows = [];
          if (hasQm) {
            const qmCols = db.raw.prepare("PRAGMA table_info(qr_messages)").all();
            const qmColNames = qmCols.map(c => c.name);
            qmRows = db.raw.prepare(`SELECT ${qmColNames.map(c => `"${c}"`).join(', ')} FROM qr_messages`).all();
            db.raw.exec(`DROP TABLE qr_messages`);
          }

          const an = db.raw.prepare("SELECT sql FROM sqlite_master WHERE name='analytics'").get();
          const hasAn = !!an;
          let anRows = [];
          if (hasAn) {
            const anCols = db.raw.prepare("PRAGMA table_info(analytics)").all();
            const anColNames = anCols.map(c => c.name);
            anRows = db.raw.prepare(`SELECT ${anColNames.map(c => `"${c}"`).join(', ')} FROM analytics`).all();
            db.raw.exec(`DROP TABLE analytics`);
          }

          db.raw.exec(`ALTER TABLE qr_codes RENAME TO qr_codes_old`);
          db.raw.exec(SCHEMA_SQLITE);
          const rows = db.raw.prepare(`SELECT ${colList} FROM qr_codes_old`).all();
          const ins = db.raw.prepare(`INSERT INTO qr_codes (${colList}) VALUES (${placeholders})`);
          for (const r of rows) ins.run(...colNames.map(n => r[n]));
          db.raw.exec(`DROP TABLE qr_codes_old`);

          if (hasFu && fuRows.length > 0) {
            const fuColInfo = db.raw.prepare("PRAGMA table_info(file_uploads)").all();
            const fuColNames = fuColInfo.map(c => c.name);
            const fuPlaceholders = fuColNames.map(() => '?').join(', ');
            const ins2 = db.raw.prepare(`INSERT INTO file_uploads (${fuColNames.map(c => `"${c}"`).join(', ')}) VALUES (${fuPlaceholders})`);
            for (const r of fuRows) ins2.run(...fuColNames.map(n => r[n]));
            console.log(`  ✓ Migrated ${fuRows.length} file_uploads rows`);
          }

          if (hasQm && qmRows.length > 0) {
            const qmColInfo = db.raw.prepare("PRAGMA table_info(qr_messages)").all();
            const qmColNames = qmColInfo.map(c => c.name);
            const qmPlaceholders = qmColNames.map(() => '?').join(', ');
            const ins3 = db.raw.prepare(`INSERT INTO qr_messages (${qmColNames.map(c => `"${c}"`).join(', ')}) VALUES (${qmPlaceholders})`);
            for (const r of qmRows) ins3.run(...qmColNames.map(n => r[n]));
            console.log(`  ✓ Migrated ${qmRows.length} qr_messages rows`);
          }

          if (hasAn && anRows.length > 0) {
            const anColInfo = db.raw.prepare("PRAGMA table_info(analytics)").all();
            const anColNames = anColInfo.map(c => c.name);
            const anPlaceholders = anColNames.map(() => '?').join(', ');
            const ins4 = db.raw.prepare(`INSERT INTO analytics (${anColNames.map(c => `"${c}"`).join(', ')}) VALUES (${anPlaceholders})`);
            for (const r of anRows) ins4.run(...anColNames.map(n => r[n]));
            console.log(`  ✓ Migrated ${anRows.length} analytics rows`);
          }

          db.raw.pragma('foreign_keys = ON');
          return rows.length;
        });
        const n = tx();
        console.log(`  ✓ Migrated ${n} qr_codes rows`);
        stmtCache.clear();
        console.log('  ✓ Prepared statement cache cleared');
      }
    } catch (e) {
      console.error('  ! CHECK-constraint migration error:', e.message);
    }
  }
}

async function ensureAdmin() {
  try {
    const countRow = await q.get("SELECT COUNT(*) as count FROM users WHERE role = 'admin'");
    const adminCount = parseInt(countRow.count);
    if (adminCount > 0) return;
    const totalRow = await q.get('SELECT COUNT(*) as count FROM users');
    const userCount = parseInt(totalRow.count);
    if (userCount > 0) {
      const firstUser = await q.get('SELECT id FROM users ORDER BY id ASC LIMIT 1');
      await q.run('UPDATE users SET role = ? WHERE id = ?', ['admin', firstUser.id]);
      console.log(`  ✓ User ${firstUser.id} promoted to admin`);
    } else {
      const bcrypt = require('bcryptjs');
      const hash = await bcrypt.hash('admin123', 12);
      await q.run('INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)', ['admin@armada.com', hash, 'Admin', 'admin']);
      console.log('  ✓ Default admin created: admin@armada.com / admin123');
    }
  } catch (e) {
    console.error('Admin check error:', e.message);
  }
}

module.exports = { db, initialize, ensureAdmin, migrateV2, getDb };
