#!/bin/bash
#
# MyFSIO Uninstall Script
# This script removes MyFSIO from your system.
#
# Usage:
#   ./uninstall.sh [OPTIONS]
#
# Options:
#   --keep-data         Don't remove data directory
#   --keep-logs         Don't remove log directory
#   --install-dir DIR   Installation directory (default: /opt/myfsio)
#   --data-dir DIR      Data directory (default: /var/lib/myfsio)
#   --log-dir DIR       Log directory (default: /var/log/myfsio)
#   --user USER         System user (default: myfsio)
#   -y, --yes           Skip confirmation prompts
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Default values
INSTALL_DIR="/opt/myfsio"
DATA_DIR="/var/lib/myfsio"
LOG_DIR="/var/log/myfsio"
SERVICE_USER="myfsio"
KEEP_DATA=false
KEEP_LOGS=false
AUTO_YES=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-data)
            KEEP_DATA=true
            shift
            ;;
        --keep-logs)
            KEEP_LOGS=true
            shift
            ;;
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
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -h|--help)
            head -20 "$0" | tail -15
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                 MyFSIO Uninstallation                    ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

echo -e "${YELLOW}The following will be removed:${NC}"
echo "  Install directory: $INSTALL_DIR"
if [[ "$KEEP_DATA" != true ]]; then
    echo -e "  Data directory:    $DATA_DIR ${RED}(ALL YOUR DATA!)${NC}"
else
    echo "  Data directory:    $DATA_DIR (KEPT)"
fi
if [[ "$KEEP_LOGS" != true ]]; then
    echo "  Log directory:     $LOG_DIR"
else
    echo "  Log directory:     $LOG_DIR (KEPT)"
fi
echo "  Systemd service:   /etc/systemd/system/myfsio.service"
echo "  System user:       $SERVICE_USER"
echo ""

if [[ "$AUTO_YES" != true ]]; then
    echo -e "${RED}WARNING: This action cannot be undone!${NC}"
    read -p "Are you sure you want to uninstall MyFSIO? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstallation cancelled."
        exit 0
    fi
fi

echo ""
echo -e "${GREEN}[1/5]${NC} Stopping service..."
if systemctl is-active --quiet myfsio 2>/dev/null; then
    systemctl stop myfsio
    echo "  Stopped myfsio service"
else
    echo "  Service not running"
fi

echo -e "${GREEN}[2/5]${NC} Disabling service..."
if systemctl is-enabled --quiet myfsio 2>/dev/null; then
    systemctl disable myfsio
    echo "  Disabled myfsio service"
else
    echo "  Service not enabled"
fi

echo -e "${GREEN}[3/5]${NC} Removing systemd service..."
if [[ -f /etc/systemd/system/myfsio.service ]]; then
    rm -f /etc/systemd/system/myfsio.service
    systemctl daemon-reload
    echo "  Removed /etc/systemd/system/myfsio.service"
else
    echo "  Service file not found"
fi

echo -e "${GREEN}[4/5]${NC} Removing directories..."
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo "  Removed $INSTALL_DIR"
fi

if [[ "$KEEP_DATA" != true ]] && [[ -d "$DATA_DIR" ]]; then
    rm -rf "$DATA_DIR"
    echo "  Removed $DATA_DIR"
elif [[ "$KEEP_DATA" == true ]]; then
    echo "  Kept $DATA_DIR"
fi

if [[ "$KEEP_LOGS" != true ]] && [[ -d "$LOG_DIR" ]]; then
    rm -rf "$LOG_DIR"
    echo "  Removed $LOG_DIR"
elif [[ "$KEEP_LOGS" == true ]]; then
    echo "  Kept $LOG_DIR"
fi

echo -e "${GREEN}[5/5]${NC} Removing system user..."
if id "$SERVICE_USER" &>/dev/null; then
    userdel "$SERVICE_USER" 2>/dev/null || true
    echo "  Removed user '$SERVICE_USER'"
else
    echo "  User not found"
fi

echo ""
echo -e "${GREEN}MyFSIO has been uninstalled.${NC}"
if [[ "$KEEP_DATA" == true ]]; then
    echo -e "${YELLOW}Data preserved at: $DATA_DIR${NC}"
fi
