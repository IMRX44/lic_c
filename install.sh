#!/bin/bash
# ═══════════════════════════════════════════════════════
#  LicenseSystem — Install Script
#  Ubuntu 22.04 / 24.04
#  اجرا: bash install.sh
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
[[ $EUID -ne 0 ]] && error "این اسکریپت باید با root اجرا شود: sudo bash install.sh"

# ─── Gather config ────────────────────────────────────────────────
info "تنظیمات نصب را وارد کنید:"
echo ""

read -p "  دامنه یا IP سرور (مثلاً: license.mysite.com یا 1.2.3.4): " DOMAIN
[[ -z "$DOMAIN" ]] && error "دامنه یا IP لازم است"

read -p "  ایمیل ادمین: " ADMIN_EMAIL
[[ -z "$ADMIN_EMAIL" ]] && ADMIN_EMAIL="admin@${DOMAIN}"

while true; do
  read -s -p "  رمز ادمین (حداقل ۱۲ کاراکتر): " ADMIN_PASS; echo ""
  [[ ${#ADMIN_PASS} -ge 12 ]] && break
  warn "رمز باید حداقل ۱۲ کاراکتر باشد"
done

read -p "  آیا SSL/TLS با Let's Encrypt می‌خواهید؟ (y/n) [y]: " USE_SSL
USE_SSL=${USE_SSL:-y}

if [[ "$USE_SSL" == "y" ]]; then
  read -p "  ایمیل برای Let's Encrypt: " SSL_EMAIL
  [[ -z "$SSL_EMAIL" ]] && SSL_EMAIL="$ADMIN_EMAIL"
fi

echo ""
info "شروع نصب..."
echo ""

# ─── Install Docker ───────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "نصب Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
  success "Docker نصب شد"
else
  success "Docker از قبل نصب است"
fi

if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null 2>&1; then
  info "نصب Docker Compose..."
  curl -SL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
  success "Docker Compose نصب شد"
else
  success "Docker Compose از قبل نصب است"
fi

# ─── Clone / Copy project ─────────────────────────────────────────
info "آماده‌سازی پروژه در $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"

if [[ -f "$(dirname "$0")/server/app/main.py" ]]; then
  # Running from repo directory
  cp -r "$(dirname "$0")/server/." "$INSTALL_DIR/"
else
  error "این اسکریپت باید از داخل پوشه‌ی پروژه اجرا شود"
fi

# ─── Generate secrets ─────────────────────────────────────────────
info "تولید کلیدهای امنیتی..."
SECRET_KEY=$(openssl rand -hex 32)
PG_PASS=$(openssl rand -hex 16)
REDIS_PASS=$(openssl rand -hex 16)

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
success ".env ساخته شد"

# ─── Update docker-compose with real passwords ────────────────────
sed -i "s/\${POSTGRES_PASSWORD:-changeme}/${PG_PASS}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${REDIS_PASSWORD:-changeme}/${REDIS_PASS}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${SECRET_KEY:-change-this-in-production}/${SECRET_KEY}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${ADMIN_EMAIL:-admin@yourdomain.com}/${ADMIN_EMAIL}/g" "$INSTALL_DIR/docker-compose.yml"
sed -i "s/\${ADMIN_PASSWORD:-change-this}/${ADMIN_PASS}/g" "$INSTALL_DIR/docker-compose.yml"

# ─── SSL Setup ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/certs"

if [[ "$USE_SSL" == "y" ]]; then
  info "نصب Certbot..."
  apt-get update -qq
  apt-get install -y -qq certbot

  # Temporarily stop port 80 if anything is running
  fuser -k 80/tcp 2>/dev/null || true

  info "دریافت گواهی SSL..."
  certbot certonly --standalone \
    --non-interactive \
    --agree-tos \
    --email "$SSL_EMAIL" \
    -d "$DOMAIN" || warn "SSL ناموفق بود — با self-signed ادامه می‌دهیم"

  if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$INSTALL_DIR/certs/"
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$INSTALL_DIR/certs/"
    # Auto-renew cron
    (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet && cp /etc/letsencrypt/live/${DOMAIN}/fullchain.pem ${INSTALL_DIR}/certs/ && cp /etc/letsencrypt/live/${DOMAIN}/privkey.pem ${INSTALL_DIR}/certs/ && docker compose -f ${INSTALL_DIR}/docker-compose.yml restart nginx") | crontab -
    success "SSL گواهی دریافت شد"
    SSL_OK=true
  else
    warn "SSL ناموفق — self-signed گواهی می‌سازیم"
    SSL_OK=false
  fi
else
  SSL_OK=false
fi

if [[ "$SSL_OK" != "true" ]]; then
  info "ساخت self-signed certificate..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$INSTALL_DIR/certs/privkey.pem" \
    -out "$INSTALL_DIR/certs/fullchain.pem" \
    -subj "/CN=${DOMAIN}" 2>/dev/null
  warn "Self-signed certificate ساخته شد (مرورگر هشدار می‌دهد)"
fi

# ─── Update nginx.conf with domain ───────────────────────────────
sed -i "s/yourdomain.com/${DOMAIN}/g" "$INSTALL_DIR/nginx.conf"

# ─── Build and start ──────────────────────────────────────────────
info "Build و start کردن Docker..."
cd "$INSTALL_DIR"
docker compose up -d --build

# ─── Systemd service (auto-restart on reboot) ─────────────────────
info "ساخت systemd service..."
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
success "Systemd service فعال شد (بعد از ریبوت هم اجرا می‌شود)"

# ─── Wait for server to be ready ──────────────────────────────────
info "منتظر راه‌اندازی سرور..."
for i in $(seq 1 30); do
  if curl -sf "http://localhost:8000/health" &>/dev/null; then
    break
  fi
  sleep 2
done

# ─── Get Ed25519 public key ───────────────────────────────────────
info "دریافت کلید عمومی Ed25519..."
sleep 3
PUB_KEY=$(docker compose exec -T app python3 -c "
from app.crypto import load_or_generate_keys, get_public_key_hex
load_or_generate_keys('/keys/ed25519_private.pem', '/keys/ed25519_public.pem')
print(get_public_key_hex())
" 2>/dev/null || echo "")

# ─── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ نصب کامل شد!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  🌐 پنل ادمین:  ${BLUE}https://${DOMAIN}/panel${NC}"
echo -e "  📧 ایمیل:      ${YELLOW}${ADMIN_EMAIL}${NC}"
echo -e "  🔑 رمز:        ${YELLOW}${ADMIN_PASS}${NC}"
echo ""
if [[ -n "$PUB_KEY" ]]; then
echo -e "  🔐 کلید عمومی Ed25519 (برای build کلاینت):"
echo -e "  ${YELLOW}${PUB_KEY}${NC}"
echo ""
echo -e "  این کلید را برای build کلاینت Rust نگه دارید:"
echo -e "  ${BLUE}export SERVER_PUBLIC_KEY_HEX=\"${PUB_KEY}\"${NC}"
echo -e "  ${BLUE}export LICENSE_SERVER_URL=\"https://${DOMAIN}\"${NC}"
fi
echo ""
echo -e "  📂 پروژه:      ${INSTALL_DIR}"
echo -e "  📋 لاگ:        ${BLUE}docker compose -C ${INSTALL_DIR} logs -f app${NC}"
echo -e "  🔄 ریستارت:    ${BLUE}systemctl restart ${SERVICE_NAME}${NC}"
echo ""

# Save info to file
cat > "$INSTALL_DIR/install-info.txt" <<EOF
Install Date: $(date)
Domain: ${DOMAIN}
Admin Email: ${ADMIN_EMAIL}
Panel URL: https://${DOMAIN}/panel
ED25519 Public Key: ${PUB_KEY}
EOF
chmod 600 "$INSTALL_DIR/install-info.txt"
success "اطلاعات نصب در $INSTALL_DIR/install-info.txt ذخیره شد"
