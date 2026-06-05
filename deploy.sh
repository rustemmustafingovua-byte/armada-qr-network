#!/usr/bin/env bash
# deploy.sh — один раз настрой, потом просто: ./deploy.sh

set -euo pipefail

RAILWAY_TOKEN="${RAILWAY_TOKEN:-}"
JWT_SECRET="${JWT_SECRET:-$(openssl rand -hex 32)}"
PUBLIC_URL="${PUBLIC_URL:-https://armada-qr-network-production-5f09.up.railway.app}"

if [[ -z "$RAILWAY_TOKEN" ]]; then
  echo "❌ RAILWAY_TOKEN not set. Get it: railway login && railway token"
  echo "   export RAILWAY_TOKEN=xxx && ./deploy.sh"
  exit 1
fi

echo "🚀 Deploying to Railway..."
npm install -g @railway/cli 2>/dev/null || true

echo "$RAILWAY_TOKEN" | railway login --token-stdin

railway variables set JWT_SECRET="$JWT_SECRET"
railway variables set NODE_ENV=production
railway variables set PUBLIC_URL="$PUBLIC_URL"

echo "📦 Deploying..."
railway up --detach

echo "⏳ Waiting for healthcheck..."
for i in {1..12}; do
  sleep 10
  if curl -sf "$PUBLIC_URL/health" | grep -q '"status":"ok"'; then
    echo "✅ Deploy successful: $PUBLIC_URL"
    exit 0
  fi
  echo "  attempt $i/12..."
done
echo "❌ Healthcheck failed"
exit 1
