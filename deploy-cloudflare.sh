#!/usr/bin/env bash
# deploy-cloudflare.sh — Deploy Armada QR Network via Cloudflare Tunnel
# This exposes your local server to the internet for FREE with a permanent HTTPS URL
#
# Prerequisites:
#   1. Install cloudflared: brew install cloudflare/cloudflare/cloudflared (macOS)
#      or curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
#   2. Authenticate: cloudflared tunnel login
#   3. Run this script

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TUNNEL_NAME="${TUNNEL_NAME:-armada-qr}"
PORT="${PORT:-3000}"
LOG_DIR="${SCRIPT_DIR}/logs"

mkdir -p "$LOG_DIR"

echo "═══════════════════════════════════════════════════"
echo "  Armada QR Network — Cloudflare Tunnel Deploy"
echo "═══════════════════════════════════════════════════"
echo ""

# Check cloudflared is installed
if ! command -v cloudflared &>/dev/null; then
  echo "❌ cloudflared not found. Install it:"
  echo "   macOS: brew install cloudflare/cloudflare/cloudflared"
  echo "   Linux: curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
  echo "          echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared $(lsb_release -cs) main' | sudo tee /etc/apt/sources.list.d/cloudflared.list"
  echo "          sudo apt update && sudo apt install -y cloudflared"
  exit 1
fi

# Check if authenticated
if [ ! -f "$HOME/.cloudflared/cert.pem" ]; then
  echo "❌ Not authenticated. Run: cloudflared tunnel login"
  exit 1
fi

echo "✓ cloudflared installed and authenticated"

# Create tunnel if it doesn't exist
if ! cloudflared tunnel list | grep -q "$TUNNEL_NAME"; then
  echo "📦 Creating tunnel: $TUNNEL_NAME"
  cloudflared tunnel create "$TUNNEL_NAME"
else
  echo "✓ Tunnel '$TUNNEL_NAME' already exists"
fi

TUNNEL_ID=$(cloudflared tunnel list | grep "$TUNNEL_NAME" | awk '{print $1}')

# Generate config
CONFIG_FILE="${SCRIPT_DIR}/cloudflared-config.yml"
cat > "$CONFIG_FILE" <<EOF
tunnel: ${TUNNEL_ID}
credentials-file: ${HOME}/.cloudflared/${TUNNEL_ID}.json

ingress:
  - hostname: ${PUBLIC_URL:-}
    service: http://localhost:${PORT}
  - hostname: ${TUNNEL_NAME}.*
    service: http://localhost:${PORT}
  - service: http_status:404
EOF

echo "✓ Config written to $CONFIG_FILE"

# Start the app with PM2 if not running
if command -v pm2 &>/dev/null; then
  if pm2 list | grep -q "armada-qr"; then
    echo "✓ App already running in PM2"
  else
    echo "🚀 Starting app with PM2..."
    cd "$SCRIPT_DIR"
    pm2 start ecosystem.config.js
    pm2 save
  fi
else
  echo "⚠ PM2 not found. Starting app directly..."
  cd "$SCRIPT_DIR"
  node server.js &
  APP_PID=$!
  echo "✓ App started (PID: $APP_PID)"
fi

# Start the tunnel
echo ""
echo "🌐 Starting Cloudflare Tunnel..."
echo "   Your QR network will be accessible at:"
if [ -n "${PUBLIC_URL:-}" ]; then
  echo "   → $PUBLIC_URL"
else
  echo "   → https://${TUNNEL_NAME}.cfargotunnel.com"
fi
echo ""
echo "   Press Ctrl+C to stop"
echo ""

cloudflared tunnel --config "$CONFIG_FILE" run "$TUNNEL_NAME"
