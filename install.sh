#!/bin/bash
# ═══════════════════════════════════════════════════════
#  LicenseSystem — Install Script
#  Ubuntu 22.04 / 24.04
#  Usage: sudo bash install.sh
# ═══════════════════════════════════════════════════════
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

INSTALL_DIR="/opt/licensesystem"
SERVICE_NAME="licensesystem"

echo -e "${BLUE}"
echo "  ██╗     ██╗ ██████╗███████╗███╗   ██╗███████╗███████╗"
echo "  ██║     ██║██╔════╝██╔════╝████╗  ██║██╔════╝██╔════╝"
echo "  ██║     ██║██║     █████╗  ██╔██╗ ██║███████╗█████╗  "
echo "  ██║     ██║██║     ██╔══╝  ██║╚██╗██║╚════██║██╔══╝  "
echo "  ███████╗██║╚██████╗███████╗██║ ╚████║███████║███████╗"
echo "  ╚══════╝╚═╝ ╚═════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo "  LicenseSystem Installer"
echo "  ─────────────────────────────────────────────────────"
echo ""

# ─── Check root ───────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Must run as root: sudo bash install.sh"

# ─── Gather config ────────────────────────────────────────────────
info "Enter installation settings:"
echo ""

read -p "  Server domain or IP (e.g. license.mysite.com or 1.2.3.4): " DOMAIN
[[ -z "$DOMAIN" ]] && error "Domain or IP is required"

read -p "  Admin email: " ADMIN_EMAIL
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"

while true; do
  read -s -p "  Admin password (minimum 12 characters): " ADMIN_PASS; echo ""
  [[ ${#ADMIN_PASS} -ge 12 ]] && break
  warn "Password must be at least 12 characters"
done

read -p "  Enable SSL/TLS with Let's Encrypt? (y/n) [y]: " USE_SSL
USE_SSL=${USE_SSL:-y}

if [[ "$USE_SSL" == "y" ]]; then
  read -p "  Email for Let's Encrypt: " SSL_EMAIL
  [[ -z "$SSL_EMAIL" ]] && SSL_EMAIL="$ADMIN_EMAIL"
fi

echo ""
info "Starting installation..."
echo ""

# ─── Install Docker ───────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
  success "Docker installed"
else
  success "Docker already installed"
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  info "Installing Docker Compose..."
  curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  success "Docker Compose installed"
else
  success "Docker Compose already installed"
fi

# ─── Clone / Copy project ─────────────────────────────────────────
info "Preparing project in $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"

if [[ -f "$(dirname "$0")/server/app/main.py" ]]; then
  # Running from repo directory
  cp -r "$(dirname "$0")/server/." "$INSTALL_DIR/"
else
  error "This script must be run from inside the project directory"
fi

# ─── Generate secrets ─────────────────────────────────────────────
info "Generating security keys..."
SECRET_KEY=$(openssl rand -hex 32)
PG_PASS=$(openssl rand -hex 16)
REDIS_PASS=$(openssl rand -hex 16)
# Random port between 20000-60000 (avoids well-known port ranges)
APP_PORT=$(( RANDOM % 40000 + 20000 ))

mkdir -p "$INSTALL_DIR/keys"

# ─── Write .env ───────────────────────────────────────────────────
cat > "$INSTALL_DIR/.env" <<EOF
DATABASE_URL=postgresql+asyncpg://licuser:${PG_PASS}@db:5432/licensedb
REDIS_URL=redis://:${REDIS_PASS}@redis:6379/0
SECRET_KEY=${SECRET_KEY}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASS}
ED25519_PRIVATE_KEY_PATH=/keys/ed25519_private.pem
ED25519_PUBLIC_KEY_PATH=/keys/ed25519_public.pem
APP_HOST=0.0.0.0
APP_PORT=8000
APP_DEBUG=false
DOMAIN=https://${DOMAIN}
POSTGRES_PASSWORD=${PG_PASS}
REDIS_PASSWORD=${REDIS_PASS}
EOF
chmod 600 "$INSTALL_DIR/.env"
success ".env created"

# ─── Update docker-compose with real passwords ────────────────────
sed -i "s/\${POSTGRES_PASSWORD:-changeme}/${PG_PASS}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${REDIS_PASSWORD:-changeme}/${REDIS_PASS}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${SECRET_KEY:-change-this-in-production}/${SECRET_KEY}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${ADMIN_EMAIL:-admin@yourdomain.com}/${ADMIN_EMAIL}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${ADMIN_PASSWORD:-change-this}/${ADMIN_PASS}/g" "$INSTALL_DIR/docker-compose.yml"

# ─── SSL Setup ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/certs"

if [[ "$USE_SSL" == "y" ]]; then
  info "Installing Certbot..."
  apt-get update -qq
  apt-get install -y -qq certbot

  # Temporarily stop port 80 if anything is running
  fuser -k 80/tcp 2>/dev/null || true

  info "Obtaining SSL certificate..."
  certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email "$SSL_EMAIL" \
    -d "$DOMAIN" || warn "SSL failed — continuing with self-signed certificate"

  if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$INSTALL_DIR/certs/"
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$INSTALL_DIR/certs/"
    # Auto-renew cron
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${INSTALL_DIR}/certs/ && cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${INSTALL_DIR}/certs/ && docker compose -f ${INSTALL_DIR}/docker-compose.yml restart nginx") | crontab -
    success "SSL certificate obtained"
    SSL_OK=true
  else
    warn "SSL failed — generating self-signed certificate"
    SSL_OK=false
  fi
else
  SSL_OK=false
fi

if [[ "$SSL_OK" != "true" ]]; then
  info "Generating self-signed certificate..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/certs/privkey.pem" \
    -out "$INSTALL_DIR/certs/fullchain.pem" \
    -subj "/CN=${DOMAIN}" 2>/dev/null
  warn "Self-signed certificate created (browser will show a warning)"
fi

# ─── Update nginx.conf with domain ───────────────────────────────
sed -i "s/yourdomain.com/${DOMAIN}/g" "$INSTALL_DIR/nginx.conf"

# Write nginx config — nginx inside container always listens on 80 (HTTP) or 443 (HTTPS)
# The random port is only on the host side of the Docker port mapping
if [[ "$SSL_OK" == "true" ]]; then
  cat > "$INSTALL_DIR/nginx.conf" <<NGINXEOF
server {
    listen 443 ssl;
    server_name ${DOMAIN};

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header Strict-Transport-Security "max-age=31536000" always;

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
    location /admin { proxy_pass http://app:8000; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /static/ { proxy_pass http://app:8000; }
    location /health { proxy_pass http://app:8000; access_log off; }
    location / { proxy_pass http://app:8000; proxy_set_header Host \$host; }
}
NGINXEOF
else
  cat > "$INSTALL_DIR/nginx.conf" <<NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};

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
    location /admin { proxy_pass http://app:8000; proxy_set_header Host \$host; proxy_set_header X-Forwarded-For \$remote_addr; }
    location /static/ { proxy_pass http://app:8000; }
    location /health { proxy_pass http://app:8000; access_log off; }
    location / { proxy_pass http://app:8000; proxy_set_header Host \$host; }
}
NGINXEOF
fi

# ─── Build and start ──────────────────────────────────────────────
info "Building and starting Docker containers..."
cd "$INSTALL_DIR"
docker compose up -d --build

# ─── Systemd service (auto-restart on reboot) ─────────────────────
info "Creating systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=LicenseSystem
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up
ExecStop=/usr/bin/docker compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
success "Systemd service enabled (auto-starts on reboot)"

# ─── Update docker-compose to expose the random port ─────────────
# nginx container listens on 80 (HTTP) or 443 (HTTPS) inside; host exposes APP_PORT
if [[ "$SSL_OK" == "true" ]]; then
  sed -i "s/\"80:80\"/\"${APP_PORT}:80\"/g; s/\"443:443\"/\"${APP_PORT}:443\"/g" "$INSTALL_DIR/docker-compose.yml"
else
  sed -i "s/\"80:80\"/\"${APP_PORT}:80\"/g; s/\"443:443\"/\"${APP_PORT}:80\"/g" "$INSTALL_DIR/docker-compose.yml"
fi

# ─── Open firewall port ───────────────────────────────────────────
info "Opening firewall port ${APP_PORT}..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "${APP_PORT}/tcp"
  success "Firewall: port ${APP_PORT} opened"
fi

# ─── Wait for server to be ready ──────────────────────────────────
info "Waiting for server to start..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:${APP_PORT}/health" &>/dev/null || curl -sf "http://localhost:8000/health" &>/dev/null; then
    success "Server is ready!"
    break
  fi
  sleep 2
done

# ─── Get Ed25519 public key ───────────────────────────────────────
info "Getting Ed25519 public key..."
sleep 3
PUB_KEY=$(docker compose exec -T app python3 -c "
from app.crypto import load_or_generate_keys, get_public_key_hex
load_or_generate_keys('/keys/ed25519_private.pem', '/keys/ed25519_public.pem')
print(get_public_key_hex())
" 2>/dev/null || echo "")

# ─── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
if [[ "$SSL_OK" == "true" ]]; then
  PANEL_URL="https://${DOMAIN}:${APP_PORT}/panel"
else
  PANEL_URL="http://${DOMAIN}:${APP_PORT}/panel"
fi
echo -e "  Admin Panel:  ${BLUE}${PANEL_URL}${NC}"
echo -e "  Port:         ${YELLOW}${APP_PORT}${NC}"
echo -e "  Email:        ${YELLOW}${ADMIN_EMAIL}${NC}"
echo -e "  Password:     ${YELLOW}${ADMIN_PASS}${NC}"
echo ""
if [[ -n "$PUB_KEY" ]]; then
echo -e "  Ed25519 Public Key (for client build):"
echo -e "  ${YELLOW}${PUB_KEY}${NC}"
echo ""
echo -e "  Use these for building the Rust client:"
echo -e "  ${BLUE}export SERVER_PUBLIC_KEY_HEX=\"${PUB_KEY}\"${NC}"
echo -e "  ${BLUE}export LICENSE_SERVER_URL=\"https://${DOMAIN}\"${NC}"
fi
echo ""
echo -e "  Project Dir:   ${INSTALL_DIR}"
echo -e "  Logs:          ${BLUE}docker compose -f ${INSTALL_DIR}/docker-compose.yml logs -f app${NC}"
echo -e "  Restart:       ${BLUE}systemctl restart ${SERVICE_NAME}${NC}"
echo ""

# Save info to file
cat > "$INSTALL_DIR/install-info.txt" <<EOF
Install Date: $(date)
Domain: ${DOMAIN}
Port: ${APP_PORT}
Admin Email: ${ADMIN_EMAIL}
Panel URL: ${PANEL_URL}
ED25519 Public Key: ${PUB_KEY}
EOF
chmod 600 "$INSTALL_DIR/install-info.txt"
success "Install info saved to $INSTALL_DIR/install-info.txt"
