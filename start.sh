#!/usr/bin/env bash
# start.sh — Start Armada QR Network (auto-detects best method)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Install deps if needed
if [ ! -d "node_modules" ]; then
  echo "📦 Installing dependencies..."
  npm install --omit=dev
fi

# Create required dirs
mkdir -p logs data public/uploads db

# Check for cloudflared
if command -v cloudflared &>/dev/null && [ -f "$HOME/.cloudflared/cert.pem" ]; then
  echo "🌐 Starting with Cloudflare Tunnel..."
  echo "   Your QR network will be accessible worldwide!"
  echo ""

  # Start app
  node server.js &
  APP_PID=$!

  # Get tunnel name from env or use default
  TUNNEL_NAME="${TUNNEL_NAME:-armada-qr}"

  # Start tunnel
  cloudflared tunnel --url http://localhost:${PORT:-3000} 2>&1 | while read -r line; do
    if echo "$line" | grep -q "trycloudflare.com"; then
      URL=$(echo "$line" | grep -o "https://[^ ]*trycloudflare.com[^ ]*" | head -1)
      if [ -n "$URL" ]; then
        echo ""
        echo "═══════════════════════════════════════════════════"
        echo "  ✅ Armada QR Network is LIVE"
        echo "═══════════════════════════════════════════════════"
        echo ""
        echo "  Public URL:  $URL"
        echo "  Local:       http://localhost:${PORT:-3000}"
        echo "  Admin:       admin@armada.com / admin123"
        echo ""
        echo "  Share this URL in QR codes — works worldwide!"
        echo "  Press Ctrl+C to stop"
        echo ""
      fi
    fi
    echo "$line"
  done

  kill $APP_PID 2>/dev/null || true
  exit 0
fi

# Check for PM2
if command -v pm2 &>/dev/null && [ -f "ecosystem.config.js" ]; then
  echo "⚡ Starting with PM2..."
  pm2 start ecosystem.config.js
  pm2 save
  pm2 logs armada-qr
  exit 0
fi

# Check for Docker
if command -v docker &>/dev/null && [ -f "docker-compose.yml" ]; then
  echo "🐳 Starting with Docker..."
  docker compose up --build
  exit 0
fi

# Fallback: direct Node.js
echo "🚀 Starting with Node.js..."
echo "   Local: http://localhost:${PORT:-3000}"
echo "   Admin: admin@armada.com / admin123"
echo ""
exec node server.js
