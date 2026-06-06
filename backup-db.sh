#!/usr/bin/env bash
# backup-db.sh — Backup SQLite database locally or from remote server
# Usage:
#   ./backup-db.sh                     # Local backup
#   ./backup-db.sh <ssh-ip> <key>      # Remote backup
#   ./backup-db.sh --cron              # Add to crontab (daily at 3am)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/backups"
DB_PATH="${DB_PATH:-./db/qrmaster.db}"
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/qrmaster_${TIMESTAMP}.db"

if [ "${1:-}" = "--cron" ]; then
  # Add to crontab
  CRON_LINE="0 3 * * * cd ${SCRIPT_DIR} && ./backup-db.sh >> ${BACKUP_DIR}/backup.log 2>&1"
  (crontab -l 2>/dev/null | grep -v "backup-db.sh"; echo "$CRON_LINE") | crontab -
  echo "✓ Backup cron job added (daily at 3am)"
  echo "  Backups stored in: $BACKUP_DIR"
  echo "  Retention: $RETENTION_DAYS days"
  exit 0
fi

if [ -n "${1:-}" ] && [ "${1:-}" != "--cron" ]; then
  # Remote backup
  SERVER_IP="$1"
  SSH_KEY="${2:-~/.ssh/id_rsa}"
  REMOTE_DB="/opt/armada-qr-network/data/qrmaster.db"

  echo "📥 Backing up from $SERVER_IP..."
  scp -i "$SSH_KEY" "ubuntu@$SERVER_IP:$REMOTE_DB" "$BACKUP_FILE"
else
  # Local backup
  if [ ! -f "$DB_PATH" ]; then
    echo "❌ Database not found: $DB_PATH"
    exit 1
  fi

  echo "📥 Backing up local database..."
  cp "$DB_PATH" "$BACKUP_FILE"
fi

# Compress
gzip "$BACKUP_FILE"
COMPRESSED="${BACKUP_FILE}.gz"

# Clean old backups
find "$BACKUP_DIR" -name "qrmaster_*.db.gz" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

SIZE=$(du -h "$COMPRESSED" | cut -f1)
echo ""
echo "✅ Backup complete"
echo "   File: $COMPRESSED"
echo "   Size: $SIZE"
echo "   Retention: $RETENTION_DAYS days"

# Show backup count
COUNT=$(find "$BACKUP_DIR" -name "qrmaster_*.db.gz" | wc -l | tr -d ' ')
echo "   Total backups: $COUNT"
