#!/bin/bash
# Phantom C2 — Docker Redirector Setup
# Usage: ./setup.sh [C2_PORT] [EXTERNAL_PORT]

set -e
C2_PORT=${1:-8080}
EXTERNAL_PORT=${2:-8443}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Phantom C2 Docker Redirector Setup"
echo "[*] C2 Port     : $C2_PORT"
echo "[*] Listen Port : $EXTERNAL_PORT (localhost:$EXTERNAL_PORT)"
echo ""

# Substitute C2_PORT into nginx.conf
sed "s/C2_PORT/$C2_PORT/g" "$SCRIPT_DIR/nginx.conf" > "$SCRIPT_DIR/nginx.conf.active"
mv "$SCRIPT_DIR/nginx.conf.active" "$SCRIPT_DIR/nginx.conf"

# Update docker-compose port mapping
sed -i "s/\"8443:80\"/\"$EXTERNAL_PORT:80\"/g" "$SCRIPT_DIR/docker-compose.yml"

echo "[*] Starting redirector container..."
cd "$SCRIPT_DIR"
docker compose down 2>/dev/null || true
docker compose up -d

echo ""
echo "[+] Redirector running at http://localhost:$EXTERNAL_PORT"
echo "[+] Proxying C2 traffic to host port $C2_PORT"
echo ""
echo "[*] Test chain:"
echo "    curl -v http://localhost:$EXTERNAL_PORT/api/v1/auth"
echo ""
echo "[*] Container logs:"
docker compose logs --tail=20
