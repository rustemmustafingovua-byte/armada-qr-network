#!/usr/bin/env bash
# deploy-oracle.sh — Deploy Armada QR Network to Oracle Cloud Always Free tier
# This gives you a permanently free VM (4 ARM cores, 24GB RAM, 200GB storage)
#
# Prerequisites:
#   1. Oracle Cloud account (free tier): https://cloud.oracle.com/free
#   2. SSH key pair generated
#   3. Compute instance created (Ubuntu 22.04/24.04 ARM, VM.Standard.A1.Flex)
#
# Usage:
#   ./deploy-oracle.sh <ssh-ip> <ssh-key-path>
#   Example: ./deploy-oracle.sh 129.146.xx.xx ~/.ssh/oracle_key

set -euo pipefail

SERVER_IP="${1:-}"
SSH_KEY="${2:-~/.ssh/id_rsa}"
APP_DIR="/opt/armada-qr-network"
REPO_URL="https://github.com/rustemmustafingovua-byte/armada-qr-network.git"

if [ -z "$SERVER_IP" ]; then
  echo "Usage: $0 <server-ip> [ssh-key-path]"
  echo ""
  echo "Steps to get server IP:"
  echo "  1. Go to https://cloud.oracle.com/free"
  echo "  2. Create Compute → Instance → ARM → Ubuntu 24.04"
  echo "  3. Copy the public IP address"
  echo "  4. Run: $0 <public-ip> ~/.ssh/your-key"
  exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"
SSH_CMD="ssh $SSH_OPTS -i $SSH_KEY ubuntu@$SERVER_IP"
SCP_CMD="scp $SSH_OPTS -i $SSH_KEY"

echo "═══════════════════════════════════════════════════"
echo "  Armada QR Network — Oracle Cloud Deploy"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Target: ubuntu@$SERVER_IP"
echo ""

# Test SSH connection
echo "🔑 Testing SSH connection..."
if ! $SSH_CMD "echo '✓ SSH OK'" 2>/dev/null; then
  echo "❌ Cannot connect to $SERVER_IP via SSH"
  echo "   Check: ssh -i $SSH_KEY ubuntu@$SERVER_IP"
  exit 1
fi

# Setup server
echo "📦 Setting up server..."
$SSH_CMD <<'REMOTE_SCRIPT'
set -euo pipefail

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
if ! command -v docker &>/dev/null; then
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker ubuntu
  echo "✓ Docker installed"
else
  echo "✓ Docker already installed"
fi

# Install Docker Compose
if ! command -v docker-compose &>/dev/null; then
  sudo apt install -y docker-compose-plugin
  echo "✓ Docker Compose installed"
else
  echo "✓ Docker Compose already installed"
fi

# Install PM2 (for local deployment option)
if ! command -v pm2 &>/dev/null; then
  sudo npm install -g pm2
  echo "✓ PM2 installed"
else
  echo "✓ PM2 already installed"
fi

# Create app directory
sudo mkdir -p $APP_DIR
sudo chown ubuntu:ubuntu $APP_DIR

# Create systemd service for auto-restart
sudo tee /etc/systemd/system/armada-qr.service > /dev/null <<'EOF'
[Unit]
Description=Armada QR Network
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/armada-qr-network
ExecStartPre=/usr/bin/docker compose pull
ExecStart=/usr/bin/docker compose up --build
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
echo "✓ Systemd service created"
REMOTE_SCRIPT

# Clone/update repo
echo "📥 Deploying application..."
$SSH_CMD <<REMOTE_DEPLOY
set -euo pipefail
cd /opt/armada-qr-network

if [ -d ".git" ]; then
  git pull origin main
else
  sudo rm -rf * .* 2>/dev/null || true
  git clone $REPO_URL .
fi

# Generate JWT secret if not exists
if [ ! -f ".env" ] || ! grep -q "JWT_SECRET" .env 2>/dev/null; then
  JWT_SECRET=\$(openssl rand -hex 32)
  cat > .env <<ENVEOF
PORT=3000
JWT_SECRET=\$JWT_SECRET
NODE_ENV=production
DB_PATH=/opt/armada-qr-network/data/qrmaster.db
UPLOAD_DIR=/opt/armada-qr-network/data/uploads
MAX_SCAN_RATE=15
BCRYPT_ROUNDS=12
# Set your public URL after Cloudflare DNS setup:
# PUBLIC_URL=https://qr.yourdomain.com
ENVEOF
  echo "✓ .env created"
fi

# Create data directory
mkdir -p data logs

# Build and start
docker compose up -d --build
echo "✓ Application started"
REMOTE_DEPLOY

# Verify
echo ""
echo "⏳ Waiting for healthcheck..."
for i in {1..15}; do
  sleep 5
  STATUS=$($SSH_CMD "curl -sf http://localhost:3000/health 2>/dev/null | grep -o '\"status\":\"ok\"' || echo ''")
  if [ "$STATUS" = '"status":"ok"' ]; then
    echo ""
    echo "═══════════════════════════════════════════════════"
    echo "  ✅ DEPLOYMENT SUCCESSFUL"
    echo "═══════════════════════════════════════════════════"
    echo ""
    echo "  Server:    http://$SERVER_IP:3000"
    echo "  Health:    http://$SERVER_IP:3000/health"
    echo "  Admin:     admin@armada.com / admin123"
    echo ""
    echo "  Next steps:"
    echo "  1. Set up Cloudflare DNS for free SSL:"
    echo "     cloudflared tunnel route dns armada-qr qr.yourdomain.com"
    echo "  2. Set PUBLIC_URL in .env on the server:"
    echo "     ssh -i $SSH_KEY ubuntu@$SERVER_IP 'sudo sed -i \"s|# PUBLIC_URL=.*|PUBLIC_URL=https://qr.yourdomain.com|\" /opt/armada-qr-network/.env && sudo systemctl restart armada-qr'"
    echo "  3. Backup script: ./backup-db.sh $SERVER_IP"
    echo ""
    exit 0
  fi
  echo "  attempt $i/15..."
done

echo ""
echo "❌ Healthcheck failed. Check logs:"
echo "   ssh -i $SSH_KEY ubuntu@$SERVER_IP 'docker compose -f /opt/armada-qr-network/docker-compose.yml logs'"
exit 1
