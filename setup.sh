#!/bin/bash
# ============================================
# Judol Detector - Setup Script untuk Raspbian
# ============================================
# Jalankan: chmod +x setup.sh && sudo ./setup.sh

set -e

echo "========================================"
echo "  Judol Detector - Installer"
echo "  Optimized for Raspbian (Raspberry Pi)"
echo "========================================"
echo ""

# Warna
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$PROJECT_DIR/venv"
SERVICE_DIR="/etc/systemd/system"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check root
if [ "$EUID" -ne 0 ]; then
    log_error "Jalankan dengan sudo: sudo ./setup.sh"
    exit 1
fi

# Step 1: Install system dependencies
log_info "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip python3-dev libsqlite3-dev

# Step 2: Create virtual environment
log_info "Creating Python virtual environment..."
if [ -d "$VENV_DIR" ]; then
    log_warn "Virtual environment sudah ada, skip."
else
    python3 -m venv "$VENV_DIR"
    log_info "Virtual environment dibuat di $VENV_DIR"
fi

# Step 3: Install Python dependencies
log_info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel -q
"$VENV_DIR/bin/pip" install -r "$PROJECT_DIR/requirements.txt" -q
log_info "Dependencies installed."

# Step 4: Setup .env
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    log_warn ".env dibuat dari template. EDIT .env dengan konfigurasi Anda!"
    log_warn "  nano $PROJECT_DIR/.env"
else
    log_info ".env sudah ada."
fi

# Step 5: Create data directories
mkdir -p "$PROJECT_DIR/data"
mkdir -p "$PROJECT_DIR/reports"
mkdir -p "$PROJECT_DIR/logs"
chmod 755 "$PROJECT_DIR/data" "$PROJECT_DIR/reports" "$PROJECT_DIR/logs"
log_info "Directories dibuat."

# Step 6: Install systemd service
log_info "Installing systemd service..."

# Determine user
ACTUAL_USER=${SUDO_USER:-pi}

cat > "$SERVICE_DIR/judol-detector.service" << EOF
[Unit]
Description=Judol Detector - Sistem Deteksi Link Judi Online
After=network.target pihole-FTL.service
Wants=pihole-FTL.service

[Service]
Type=simple
User=$ACTUAL_USER
Group=$ACTUAL_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$VENV_DIR/bin/python -m judol_detector daemon
Restart=on-failure
RestartSec=30

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=judol-detector

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$PROJECT_DIR/data $PROJECT_DIR/reports $PROJECT_DIR/logs

# Resource limits untuk Raspberry Pi
MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
log_info "Systemd service installed."

# Step 7: Set permissions
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$PROJECT_DIR"

echo ""
echo "========================================"
log_info "Setup selesai!"
echo "========================================"
echo ""
echo "Langkah selanjutnya:"
echo "  1. Edit konfigurasi:"
echo "     nano $PROJECT_DIR/.env"
echo ""
echo "  2. Test scan (sekali):"
echo "     $VENV_DIR/bin/python -m judol_detector scan --dry-run"
echo ""
echo "  3. Jalankan sebagai service:"
echo "     sudo systemctl enable judol-detector"
echo "     sudo systemctl start judol-detector"
echo ""
echo "  4. Cek status:"
echo "     sudo systemctl status judol-detector"
echo "     sudo journalctl -u judol-detector -f"
echo ""
