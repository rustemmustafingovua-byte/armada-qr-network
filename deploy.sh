#!/bin/bash
# Armada QR Network - Deployment Script
# Usage: bash deploy.sh [option]

set -e

PORT=${PORT:-3000}

case "${1:-help}" in
  tunnel)
    echo "=== Starting public tunnel (localhost.run) ==="
    echo "You need an SSH key. Generate one if missing:"
    echo "  ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
    echo ""
    ssh -tt -R 80:localhost:$PORT localhost.run 2>/dev/null || \
      ssh -o PubkeyAuthentication=no -R 80:localhost:$PORT localhost.run
    ;;
    
  ngrok)
    echo "=== Starting ngrok ==="
    if ! command -v ngrok &>/dev/null; then
      echo "Installing ngrok..."
      brew install ngrok 2>/dev/null || npm install -g ngrok 2>/dev/null
    fi
    echo "NOTE: You need an authtoken. Sign up at https://dashboard.ngrok.com/signup"
    echo "Then run: ngrok config add-authtoken YOUR_TOKEN"
    echo ""
    ngrok http $PORT
    ;;
    
  docker)
    echo "=== Building and starting with Docker ==="
    docker compose up -d --build
    echo "Server running on http://localhost:$PORT"
    echo "Logs: docker compose logs -f"
    ;;
    
  deploy-vps)
    echo "=== Deploy to VPS ==="
    read -p "VPS IP address: " VPS_IP
    read -p "VPS username (root): " VPS_USER
    VPS_USER=${VPS_USER:-root}
    echo "Copying files..."
    rsync -avz --exclude node_modules --exclude .env --exclude 'db/*.db' --exclude 'public/uploads/*' ./ $VPS_USER@$VPS_IP:/opt/armada-qr/
    echo "Installing on VPS..."
    ssh $VPS_USER@$VPS_IP "cd /opt/armada-qr && npm install && node server.js" 
    ;;
    
  info)
    echo "=== Server Info ==="
    curl -s http://localhost:$PORT/api/server-info 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Server not running?"
    ;;
    
  *)
    echo "Armada QR Network - Deployment"
    echo ""
    echo "Usage: bash deploy.sh [command]"
    echo ""
    echo "Commands:"
    echo "  tunnel     Start free public tunnel (localhost.run)"
    echo "  ngrok      Start ngrok tunnel (needs free account)"
    echo "  docker     Build & run with Docker Compose"
    echo "  deploy-vps Deploy to a VPS server"
    echo "  info       Show server connection info"
    echo ""
    echo "Quick start for worldwide access:"
    echo "  1. ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''"
    echo "  2. bash deploy.sh tunnel"
    echo ""
    echo "Production:"
    echo "  bash deploy.sh docker"
    ;;
esac
