#!/bin/bash
# Fix the running deployment: switch to a random non-standard port
# Run this on the VPS as root: bash fix-port.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }

INSTALL_DIR="/opt/licensesystem"
[[ $EUID -ne 0 ]] && echo "Run as root: sudo bash fix-port.sh" && exit 1

# Pick a random port between 20000-60000
NEW_PORT=$(( RANDOM % 40000 + 20000 ))

info "Switching to port ${NEW_PORT}..."

# Write clean HTTP-only nginx.conf
cat > "${INSTALL_DIR}/nginx.conf" <<NGINXEOF
server {
    listen 80;
    server_name _;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location /api/ {
        proxy_pass http://app:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600;
    }
    location /panel { proxy_pass http://app:8000; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /admin  { proxy_pass http://app:8000; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /static/ { proxy_pass http://app:8000; }
    location /health  { proxy_pass http://app:8000; access_log off; }
    location /        { proxy_pass http://app:8000; proxy_set_header Host \$host; }
}
NGINXEOF

# Rewrite docker-compose.yml with the new port mapping (nginx listens on 80 inside, exposed as NEW_PORT outside)
cat > "${INSTALL_DIR}/docker-compose.yml" <<DCEOF
version: "3.9"
services:
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    env_file: .env
    environment:
      POSTGRES_USER: licuser
      POSTGRES_DB: licensedb
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks:
      - internal
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --requirepass \${REDIS_PASSWORD}
    volumes:
      - redisdata:/data
    networks:
      - internal
  app:
    build: .
    restart: unless-stopped
    env_file: .env
    volumes:
      - ./keys:/keys
    depends_on:
      - db
      - redis
    networks:
      - internal
      - external
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "${NEW_PORT}:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - app
    networks:
      - external
volumes:
  pgdata:
  redisdata:
networks:
  internal:
    driver: bridge
  external:
    driver: bridge
DCEOF

# Open new port in firewall
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${NEW_PORT}/tcp"
  info "Firewall: opened port ${NEW_PORT}"
fi

# Restart containers
info "Restarting containers..."
cd "${INSTALL_DIR}"
docker compose down
docker compose up -d

# Wait for health
info "Waiting for server..."
for i in $(seq 1 20); do
  if curl -sf "http://localhost:${NEW_PORT}/health" &>/dev/null; then
    success "Server is up on port ${NEW_PORT}"
    break
  fi
  sleep 3
done

# Show admin info
ADMIN_PASS=$(grep ADMIN_PASSWORD "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2 || echo "check .env")
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Done! Panel is now at:${NC}"
echo -e "${BLUE}  http://${SERVER_IP}:${NEW_PORT}/panel${NC}"
echo -e "  Password: ${YELLOW}${ADMIN_PASS}${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""

# Save port to install-info
echo "Port: ${NEW_PORT}" >> "${INSTALL_DIR}/install-info.txt"
echo "Panel URL: http://${SERVER_IP}:${NEW_PORT}/panel" >> "${INSTALL_DIR}/install-info.txt"
