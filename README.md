# Armada QR Network

Enterprise-grade dynamic QR code platform with analytics, 2FA, API, webhooks, and team management.

## Features

### Core
- **Dynamic & Static QR codes** — Edit destination without reprinting
- **6 content types**: URL, File (PDF/image/any), vCard, Text, WiFi, Calendar Event
- **Custom design** — Colors, error correction, SVG/PNG export
- **Password protection** & verification codes
- **Expiration & scan limits**

### Analytics
- Real-time scan tracking (device, OS, browser, country, referer)
- Time-series charts (30-day, hourly distribution)
- Unique visitor counting
- CSV export

### Security
- **2FA / TOTP** (Google Authenticator, Authy)
- bcrypt-12 password hashing
- CSRF protection with token rotation
- Rate limiting (login, scan, download, API)
- CSP with nonce, HSTS, X-Frame-Options DENY
- SQL-injection-safe parameterized queries
- Path traversal protection
- File magic-byte verification

### Developer
- **REST API** with bearer tokens (`armq_*`)
- **Webhooks** on scan events
- OpenAPI-compatible JSON responses
- Structured JSON logging in production
- `/health` and request IDs

### Operations
- SQLite (default) or PostgreSQL
- Graceful shutdown (SIGTERM)
- Auto-migration
- Audit log
- Data export (JSON)

## Quick Start

```bash
npm install
npm start
# → http://localhost:3000
# Default admin: admin@armada.com / admin123 (change immediately!)
```

## Environment Variables

```env
# Required
JWT_SECRET=at-least-32-characters-long-random-secret

# Optional
PORT=3000
NODE_ENV=production
BCRYPT_ROUNDS=12
DB_PATH=./db/qrmaster.db
UPLOAD_DIR=./public/uploads
MAX_SCAN_RATE=15
PUBLIC_URL=https://your-domain.com
DATABASE_URL=postgresql://user:pass@host:5432/armada_qr
```

## API

All endpoints require `Authorization: Bearer <token>` header.

```bash
# List your QRs
curl -H "Authorization: Bearer armq_..." https://your-site.com/api/v1/qr

# Create
curl -X POST -H "Authorization: Bearer armq_..." -H "Content-Type: application/json" \
  -d '{"title":"My Link","content_type":"link","target_url":"https://example.com"}' \
  https://your-site.com/api/v1/qr

# Get analytics
curl -H "Authorization: Bearer armq_..." https://your-site.com/api/v1/analytics/<id>

# Get messages
curl -H "Authorization: Bearer armq_..." https://your-site.com/api/v1/messages/<id>

# Delete
curl -X DELETE -H "Authorization: Bearer armq_..." https://your-site.com/api/v1/qr/<id>
```

## Deployment

### Railway
1. Push to GitHub
2. Connect in Railway
3. Set env vars (JWT_SECRET auto-required)
4. Add PostgreSQL plugin for production

### Docker
```bash
docker build -t armada-qr .
docker run -p 3000:3000 -e JWT_SECRET=$(openssl rand -hex 32) armada-qr
```

### Manual
```bash
NODE_ENV=production JWT_SECRET=$(openssl rand -hex 32) node server.js
```

## Architecture

```
server.js             # Express bootstrap, security, rate limits
db/
  adapter.js          # SQLite/PostgreSQL adapter
  query.js            # Promise-based query helpers
middleware/
  auth.js             # JWT cookie auth
  security.js         # Validation helpers
routes/
  auth.js             # Login, register, 2FA
  qr.js               # Create, edit, delete QRs
  redirect.js         # Public scan handler
  files.js            # File download with verify codes
  messages.js         # User messages
  analytics.js        # Charts, CSV export
  admin.js            # Admin panel
  api.js              # REST API (bearer tokens)
  settings.js         # User profile, 2FA, tokens
views/                # EJS templates
public/               # Static assets
tests/                # Unit + integration tests
utils/
  logger.js           # Structured logging + request IDs
  network.js          # URL helpers
```

## Testing

```bash
npm test               # Unit tests
node tests/integration.test.js
```

## Security Checklist

- [x] bcrypt-12 password hashing
- [x] JWT with 7-day expiry, httpOnly + SameSite=Lax cookies
- [x] CSRF token on all state-changing requests
- [x] 2FA / TOTP support
- [x] Login rate limit (10/15min) + account lockout
- [x] Scan rate limit (15/sec per IP)
- [x] File download rate limit (30/min per IP)
- [x] API rate limit (240/min per IP)
- [x] CSP with nonce (no unsafe-inline)
- [x] HSTS (1 year, includeSubDomains, preload)
- [x] X-Frame-Options: DENY
- [x] X-Content-Type-Options: nosniff
- [x] Permissions-Policy locked down
- [x] Path traversal protection
- [x] File magic-byte verification
- [x] SQL injection: 100% parameterized queries
- [x] Audit log for sensitive actions
- [x] Auto-purge old webhook deliveries
- [x] Graceful shutdown drains connections

## License

MIT
# Force rebuild Sat Jun  6 01:05:57 EEST 2026
