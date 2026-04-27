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
#   --host HOST          Bind host (default: 0.0.0.0)
#   --port PORT          API port (default: 5000)
#   --ui-port PORT       UI port (default: 5100)
#   --api-url URL        Public API URL (for presigned URLs behind proxy)
#   --no-systemd         Skip systemd service creation
#   --binary PATH        Path to myfsio binary (default: ./myfsio)
#   -y, --yes            Skip confirmation prompts
#

set -e

INSTALL_DIR="/opt/myfsio"
DATA_DIR="/var/lib/myfsio"
LOG_DIR="/var/log/myfsio"
SERVICE_USER="myfsio"
BIND_HOST="0.0.0.0"
API_PORT="5000"
UI_PORT="5100"
API_URL=""
SKIP_SYSTEMD=false
BINARY_PATH=""
AUTO_YES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
        --data-dir)     DATA_DIR="$2"; shift 2 ;;
        --log-dir)      LOG_DIR="$2"; shift 2 ;;
        --user)         SERVICE_USER="$2"; shift 2 ;;
        --host)         BIND_HOST="$2"; shift 2 ;;
        --port)         API_PORT="$2"; shift 2 ;;
        --ui-port)      UI_PORT="$2"; shift 2 ;;
        --api-url)      API_URL="$2"; shift 2 ;;
        --no-systemd)   SKIP_SYSTEMD=true; shift ;;
        --binary)       BINARY_PATH="$2"; shift 2 ;;
        -y|--yes)       AUTO_YES=true; shift ;;
        -h|--help)      head -22 "$0" | tail -17; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
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
echo "  Bind host:          $BIND_HOST"
echo "  API port:           $API_PORT"
echo "  UI port:            $UI_PORT"
[[ -n "$API_URL" ]]     && echo "  Public API URL:     $API_URL"
[[ -n "$BINARY_PATH" ]] && echo "  Binary:             $BINARY_PATH"
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
mkdir -p "$INSTALL_DIR" && echo "  [OK] Created $INSTALL_DIR"
mkdir -p "$DATA_DIR"    && echo "  [OK] Created $DATA_DIR"
mkdir -p "$LOG_DIR"     && echo "  [OK] Created $LOG_DIR"

echo ""
echo "------------------------------------------------------------"
echo "STEP 4: Installing Binary"
echo "------------------------------------------------------------"
echo ""
if [[ -n "$BINARY_PATH" ]]; then
    if [[ ! -f "$BINARY_PATH" ]]; then
        echo "  [ERROR] Binary not found at $BINARY_PATH"
        exit 1
    fi
    cp "$BINARY_PATH" "$INSTALL_DIR/myfsio"
    echo "  [OK] Copied binary from $BINARY_PATH"
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
echo "  [INFO] Templates and static UI assets are embedded in the binary"

echo ""
echo "------------------------------------------------------------"
echo "STEP 5: Creating Configuration File"
echo "------------------------------------------------------------"
echo ""

SECRET_FILE="$DATA_DIR/.myfsio.sys/config/.secret"
mkdir -p "$(dirname "$SECRET_FILE")"
if [[ -s "$SECRET_FILE" ]]; then
    echo "  [OK] Existing secret found at $SECRET_FILE - preserving"
elif [[ -n "${SECRET_KEY:-}" ]]; then
    printf '%s' "$SECRET_KEY" > "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    echo "  [OK] Wrote SECRET_KEY from environment to $SECRET_FILE"
else
    if command -v openssl &>/dev/null; then
        printf '%s' "$(openssl rand -base64 32)" > "$SECRET_FILE"
    elif [[ -r /dev/urandom ]]; then
        printf '%s' "$(head -c 32 /dev/urandom | base64)" > "$SECRET_FILE"
    else
        echo "  [ERROR] Neither openssl nor /dev/urandom available; cannot generate secret"
        exit 1
    fi
    chmod 600 "$SECRET_FILE"
    echo "  [OK] Generated secret key at $SECRET_FILE"
fi
unset SECRET_KEY

if [[ -n "$API_URL" ]]; then
    EFFECTIVE_API_URL="$API_URL"
else
    case "$BIND_HOST" in
        0.0.0.0|::|"")
            DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
            [[ -z "$DETECTED_IP" ]] && DETECTED_IP="127.0.0.1"
            EFFECTIVE_API_URL="http://$DETECTED_IP:$API_PORT"
            echo "  [INFO] Bind host is $BIND_HOST; deriving API_BASE_URL=$EFFECTIVE_API_URL"
            echo "         Pass --api-url to set a public URL for presigned access."
            ;;
        *)
            EFFECTIVE_API_URL="http://$BIND_HOST:$API_PORT"
            ;;
    esac
fi

cat > "$INSTALL_DIR/myfsio.env" << EOF
# MyFSIO Configuration
# Generated by install.sh on $(date)
# Documentation: https://go.jzwsite.com/myfsio

# =============================================================================
# STORAGE PATHS
# =============================================================================
STORAGE_ROOT=$DATA_DIR

# =============================================================================
# NETWORK
# =============================================================================
HOST=$BIND_HOST
PORT=$API_PORT
UI_PORT=$UI_PORT

# Public URL used to sign presigned URLs (override with --api-url for proxies)
API_BASE_URL=$EFFECTIVE_API_URL

# =============================================================================
# SECURITY
# =============================================================================
# CORS settings - restrict in production
CORS_ORIGINS=*
# CORS_METHODS=GET,PUT,POST,DELETE,OPTIONS,HEAD
# CORS_ALLOW_HEADERS=*
# CORS_EXPOSE_HEADERS=*

# Reverse proxy settings (number of trusted proxies in front)
# NUM_TRUSTED_PROXIES=1

# Allow internal/diagnostic admin endpoints (only on trusted networks)
# ALLOW_INTERNAL_ENDPOINTS=false

# Comma-separated external hosts allowed for UI login redirects
# ALLOWED_REDIRECT_HOSTS=

# UI session lifetime in days
# SESSION_LIFETIME_DAYS=1

# SigV4 timestamp tolerance (seconds)
# SIGV4_TIMESTAMP_TOLERANCE_SECONDS=900

# =============================================================================
# UI ASSET OVERRIDES (optional - assets are embedded in the binary by default)
# =============================================================================
# Set these only when developing UI changes against an unpacked source tree.
# TEMPLATES_DIR=/path/to/templates
# STATIC_DIR=/path/to/static

# =============================================================================
# LOGGING
# =============================================================================
LOG_LEVEL=INFO
# RUST_LOG=info,myfsio_server=info

# =============================================================================
# RATE LIMITING
# =============================================================================
RATE_LIMIT_DEFAULT=500 per minute
# RATE_LIMIT_LIST_BUCKETS=500 per minute
# RATE_LIMIT_BUCKET_OPS=500 per minute
# RATE_LIMIT_OBJECT_OPS=500 per minute
# RATE_LIMIT_HEAD_OPS=500 per minute
RATE_LIMIT_ADMIN=60 per minute

# =============================================================================
# ENCRYPTION (uncomment to enable)
# =============================================================================
# ENCRYPTION_ENABLED=true
# KMS_ENABLED=true

# =============================================================================
# SITE SYNC / REPLICATION (multi-site deployments)
# =============================================================================
# SITE_ID=site-1
# SITE_ENDPOINT=https://s3-site1.example.com
# SITE_REGION=us-east-1
# SITE_PRIORITY=100
# SITE_SYNC_ENABLED=false
# SITE_SYNC_INTERVAL_SECONDS=60
# SITE_SYNC_BATCH_SIZE=100

# =============================================================================
# OPTIONAL FEATURES
# =============================================================================
# WEBSITE_HOSTING_ENABLED=false
# LIFECYCLE_ENABLED=false
# METRICS_HISTORY_ENABLED=false
# OPERATION_METRICS_ENABLED=false
# GC_ENABLED=false
# GC_INTERVAL_HOURS=6
# GC_DRY_RUN=false
# INTEGRITY_ENABLED=false

# =============================================================================
# FIRST-RUN ADMIN OVERRIDE (optional)
# =============================================================================
# ADMIN_ACCESS_KEY=
# ADMIN_SECRET_KEY=
EOF
chmod 600 "$INSTALL_DIR/myfsio.env"
echo "  [OK] Created $INSTALL_DIR/myfsio.env"

echo ""
echo "------------------------------------------------------------"
echo "STEP 6: Setting Permissions"
echo "------------------------------------------------------------"
echo ""
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" && echo "  [OK] Set ownership for $INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"    && echo "  [OK] Set ownership for $DATA_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"     && echo "  [OK] Set ownership for $LOG_DIR"

if [[ "$SKIP_SYSTEMD" != true ]]; then
    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 7: Creating Systemd Service"
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
ExecStart=$INSTALL_DIR/myfsio serve
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR
PrivateTmp=true

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
    echo "STEP 7: Skipping Systemd Service (--no-systemd flag used)"
    echo "------------------------------------------------------------"
fi

echo ""
echo "============================================================"
echo "               Installation Complete!"
echo "============================================================"
echo ""

if [[ "$SKIP_SYSTEMD" != true ]]; then
    echo "------------------------------------------------------------"
    echo "STEP 8: Start the Service"
    echo "------------------------------------------------------------"
    echo ""

    if [[ "$AUTO_YES" != true ]]; then
        read -p "Would you like to start MyFSIO now? [Y/n] " -n 1 -r
        echo
        START_SERVICE=true
        [[ $REPLY =~ ^[Nn]$ ]] && START_SERVICE=false
    else
        START_SERVICE=true
    fi

    if [[ "$START_SERVICE" == true ]]; then
        echo "  Starting MyFSIO service..."
        systemctl start myfsio
        echo "  [OK] Service started"
        echo ""

        if [[ "$AUTO_YES" != true ]]; then
            read -p "Would you like to enable MyFSIO to start on boot? [Y/n] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Nn]$ ]]; then
                systemctl enable myfsio
                echo "  [OK] Service enabled on boot"
            fi
        else
            systemctl enable myfsio
            echo "  [OK] Service enabled on boot"
        fi
        echo ""

        echo "  Waiting for service initialization..."
        sleep 3

        echo "  Service Status:"
        echo "  ---------------"
        if systemctl is-active --quiet myfsio; then
            echo "  [OK] MyFSIO is running"
            echo ""
            echo "  ============================================"
            echo "  ADMIN CREDENTIALS (save these securely!)"
            echo "  ============================================"
            CRED_OUTPUT=$(journalctl -u myfsio --no-pager -n 100 2>/dev/null | grep -A 5 "FIRST RUN - ADMIN CREDENTIALS")
            ACCESS_KEY=$(echo "$CRED_OUTPUT" | grep "Access Key:" | head -1 | sed 's/.*Access Key: //' | awk '{print $1}')
            SECRET_KEY=$(echo "$CRED_OUTPUT" | grep "Secret Key:" | head -1 | sed 's/.*Secret Key: //' | awk '{print $1}')
            if [[ -n "$ACCESS_KEY" && -n "$SECRET_KEY" ]]; then
                echo "  Access Key: $ACCESS_KEY"
                echo "  Secret Key: $SECRET_KEY"
            else
                echo "  [!] Could not extract credentials from service logs."
                echo "      Check: journalctl -u myfsio --no-pager | grep -A 5 'ADMIN CREDENTIALS'"
                echo "      Or reset:  $INSTALL_DIR/myfsio --reset-cred"
            fi
            echo "  ============================================"
        else
            echo "  [WARNING] MyFSIO may not have started correctly"
            echo "            Check logs with: journalctl -u myfsio -f"
        fi
    else
        echo "  [SKIPPED] Service not started"
        echo ""
        echo "  Start manually:  sudo systemctl start myfsio"
        echo "  Enable on boot:  sudo systemctl enable myfsio"
    fi
fi

HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

echo ""
echo "============================================================"
echo "                      Summary"
echo "============================================================"
echo ""
echo "Access Points:"
echo "  S3 API:  http://$HOST_IP:$API_PORT"
echo "  Web UI:  http://$HOST_IP:$UI_PORT/ui"
echo ""
echo "Configuration Files:"
echo "  Environment:     $INSTALL_DIR/myfsio.env"
echo "  IAM Users:       $DATA_DIR/.myfsio.sys/config/iam.json (encrypted)"
echo "  Bucket Policies: $DATA_DIR/.myfsio.sys/config/bucket_policies.json"
echo "  Secret Key:      $DATA_DIR/.myfsio.sys/config/.secret (auto-generated)"
echo ""
echo "Useful Commands:"
echo "  Check status:     sudo systemctl status myfsio"
echo "  View logs:        sudo journalctl -u myfsio -f"
echo "  Validate config:  $INSTALL_DIR/myfsio --check-config"
echo "  Show config:      $INSTALL_DIR/myfsio --show-config"
echo "  Reset admin:      sudo -u $SERVICE_USER $INSTALL_DIR/myfsio --reset-cred"
echo "  Restart:          sudo systemctl restart myfsio"
echo "  Stop:             sudo systemctl stop myfsio"
echo ""
echo "Documentation: https://go.jzwsite.com/myfsio"
echo ""
echo "============================================================"
echo "          Thank you for installing MyFSIO!"
echo "============================================================"
echo ""
