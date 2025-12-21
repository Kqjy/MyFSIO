#!/bin/bash
#
# MyFSIO Installation Script
# This script sets up MyFSIO for production use on Linux systems.
#
# Usage:
#   ./install.sh [OPTIONS]
#
# Options:
#   --install-dir DIR    Installation directory (default: /opt/myfsio)
#   --data-dir DIR       Data directory (default: /var/lib/myfsio)
#   --log-dir DIR        Log directory (default: /var/log/myfsio)
#   --user USER          System user to run as (default: myfsio)
#   --port PORT          API port (default: 5000)
#   --ui-port PORT       UI port (default: 5100)
#   --api-url URL        Public API URL (for presigned URLs behind proxy)
#   --no-systemd         Skip systemd service creation
#   --binary PATH        Path to myfsio binary (will download if not provided)
#   -y, --yes            Skip confirmation prompts
#

set -e

INSTALL_DIR="/opt/myfsio"
DATA_DIR="/var/lib/myfsio"
LOG_DIR="/var/log/myfsio"
SERVICE_USER="myfsio"
API_PORT="5000"
UI_PORT="5100"
API_URL=""
SKIP_SYSTEMD=false
BINARY_PATH=""
AUTO_YES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --log-dir)
            LOG_DIR="$2"
            shift 2
            ;;
        --user)
            SERVICE_USER="$2"
            shift 2
            ;;
        --port)
            API_PORT="$2"
            shift 2
            ;;
        --ui-port)
            UI_PORT="$2"
            shift 2
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --no-systemd)
            SKIP_SYSTEMD=true
            shift
            ;;
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -h|--help)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo ""
echo "============================================================"
echo "               MyFSIO Installation Script"
echo "            S3-Compatible Object Storage"
echo "============================================================"
echo ""
echo "Documentation: https://go.jzwsite.com/myfsio"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

echo "------------------------------------------------------------"
echo "STEP 1: Review Installation Configuration"
echo "------------------------------------------------------------"
echo ""
echo "  Install directory:  $INSTALL_DIR"
echo "  Data directory:     $DATA_DIR"
echo "  Log directory:      $LOG_DIR"
echo "  Service user:       $SERVICE_USER"
echo "  API port:           $API_PORT"
echo "  UI port:            $UI_PORT"
if [[ -n "$API_URL" ]]; then
    echo "  Public API URL:     $API_URL"
fi
if [[ -n "$BINARY_PATH" ]]; then
    echo "  Binary path:        $BINARY_PATH"
fi
echo ""

if [[ "$AUTO_YES" != true ]]; then
    read -p "Do you want to proceed with these settings? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 2: Creating System User"
echo "------------------------------------------------------------"
echo ""
if id "$SERVICE_USER" &>/dev/null; then
    echo "  [OK] User '$SERVICE_USER' already exists"
else
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "  [OK] Created user '$SERVICE_USER'"
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 3: Creating Directories"
echo "------------------------------------------------------------"
echo ""
mkdir -p "$INSTALL_DIR"
echo "  [OK] Created $INSTALL_DIR"
mkdir -p "$DATA_DIR"
echo "  [OK] Created $DATA_DIR"
mkdir -p "$LOG_DIR"
echo "  [OK] Created $LOG_DIR"

echo ""
echo "------------------------------------------------------------"
echo "STEP 4: Installing Binary"
echo "------------------------------------------------------------"
echo ""
if [[ -n "$BINARY_PATH" ]]; then
    if [[ -f "$BINARY_PATH" ]]; then
        cp "$BINARY_PATH" "$INSTALL_DIR/myfsio"
        echo "  [OK] Copied binary from $BINARY_PATH"
    else
        echo "  [ERROR] Binary not found at $BINARY_PATH"
        exit 1
    fi
elif [[ -f "./myfsio" ]]; then
    cp "./myfsio" "$INSTALL_DIR/myfsio"
    echo "  [OK] Copied binary from ./myfsio"
else
    echo "  [ERROR] No binary provided."
    echo "          Use --binary PATH or place 'myfsio' in current directory"
    exit 1
fi
chmod +x "$INSTALL_DIR/myfsio"
echo "  [OK] Set executable permissions"

echo ""
echo "------------------------------------------------------------"
echo "STEP 5: Generating Secret Key"
echo "------------------------------------------------------------"
echo ""
SECRET_KEY=$(openssl rand -base64 32)
echo "  [OK] Generated secure SECRET_KEY"

echo ""
echo "------------------------------------------------------------"
echo "STEP 6: Creating Configuration File"
echo "------------------------------------------------------------"
echo ""
cat > "$INSTALL_DIR/myfsio.env" << EOF
# MyFSIO Configuration
# Generated by install.sh on $(date)
# Documentation: https://go.jzwsite.com/myfsio

# Storage paths
STORAGE_ROOT=$DATA_DIR
LOG_DIR=$LOG_DIR

# Network
APP_HOST=0.0.0.0
APP_PORT=$API_PORT

# Security - CHANGE IN PRODUCTION
SECRET_KEY=$SECRET_KEY
CORS_ORIGINS=*

# Public URL (set this if behind a reverse proxy)
$(if [[ -n "$API_URL" ]]; then echo "API_BASE_URL=$API_URL"; else echo "# API_BASE_URL=https://s3.example.com"; fi)

# Logging
LOG_LEVEL=INFO
LOG_TO_FILE=true

# Rate limiting
RATE_LIMIT_DEFAULT=200 per minute

# Optional: Encryption (uncomment to enable)
# ENCRYPTION_ENABLED=true
# KMS_ENABLED=true
EOF
chmod 600 "$INSTALL_DIR/myfsio.env"
echo "  [OK] Created $INSTALL_DIR/myfsio.env"

echo ""
echo "------------------------------------------------------------"
echo "STEP 7: Setting Permissions"
echo "------------------------------------------------------------"
echo ""
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
echo "  [OK] Set ownership for $INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
echo "  [OK] Set ownership for $DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
echo "  [OK] Set ownership for $LOG_DIR"

if [[ "$SKIP_SYSTEMD" != true ]]; then
    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 8: Creating Systemd Service"
    echo "------------------------------------------------------------"
    echo ""
    cat > /etc/systemd/system/myfsio.service << EOF
[Unit]
Description=MyFSIO S3-Compatible Storage
Documentation=https://go.jzwsite.com/myfsio
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/myfsio.env
ExecStart=$INSTALL_DIR/myfsio
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR
PrivateTmp=true

# Resource limits (adjust as needed)
# LimitNOFILE=65535
# MemoryMax=2G

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo "  [OK] Created /etc/systemd/system/myfsio.service"
    echo "  [OK] Reloaded systemd daemon"
else
    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 8: Skipping Systemd Service (--no-systemd flag used)"
    echo "------------------------------------------------------------"
fi

echo ""
echo "============================================================"
echo "               Installation Complete!"
echo "============================================================"
echo ""

if [[ "$SKIP_SYSTEMD" != true ]]; then
    echo "------------------------------------------------------------"
    echo "STEP 9: Start the Service"
    echo "------------------------------------------------------------"
    echo ""
    
    if [[ "$AUTO_YES" != true ]]; then
        read -p "Would you like to start MyFSIO now? [Y/n] " -n 1 -r
        echo
        START_SERVICE=true
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            START_SERVICE=false
        fi
    else
        START_SERVICE=true
    fi
    
    if [[ "$START_SERVICE" == true ]]; then
        echo "  Starting MyFSIO service..."
        systemctl start myfsio
        echo "  [OK] Service started"
        echo ""
        
        read -p "Would you like to enable MyFSIO to start on boot? [Y/n] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            systemctl enable myfsio
            echo "  [OK] Service enabled on boot"
        fi
        echo ""
        
        sleep 2
        echo "  Service Status:"
        echo "  ---------------"
        if systemctl is-active --quiet myfsio; then
            echo "  [OK] MyFSIO is running"
        else
            echo "  [WARNING] MyFSIO may not have started correctly"
            echo "            Check logs with: journalctl -u myfsio -f"
        fi
    else
        echo "  [SKIPPED] Service not started"
        echo ""
        echo "  To start manually, run:"
        echo "    sudo systemctl start myfsio"
        echo ""
        echo "  To enable on boot, run:"
        echo "    sudo systemctl enable myfsio"
    fi
fi

echo ""
echo "============================================================"
echo "                      Summary"
echo "============================================================"
echo ""
echo "Access Points:"
echo "  API:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost"):$API_PORT"
echo "  UI:   http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost"):$UI_PORT/ui"
echo ""
echo "Default Credentials:"
echo "  Username: localadmin"
echo "  Password: localadmin"
echo "  [!] WARNING: Change these immediately after first login!"
echo ""
echo "Configuration Files:"
echo "  Environment:     $INSTALL_DIR/myfsio.env"
echo "  IAM Users:       $DATA_DIR/.myfsio.sys/config/iam.json"
echo "  Bucket Policies: $DATA_DIR/.myfsio.sys/config/bucket_policies.json"
echo ""
echo "Useful Commands:"
echo "  Check status:    sudo systemctl status myfsio"
echo "  View logs:       sudo journalctl -u myfsio -f"
echo "  Restart:         sudo systemctl restart myfsio"
echo "  Stop:            sudo systemctl stop myfsio"
echo ""
echo "Documentation: https://go.jzwsite.com/myfsio"
echo ""
echo "============================================================"
echo "          Thank you for installing MyFSIO!"
echo "============================================================"
echo ""
