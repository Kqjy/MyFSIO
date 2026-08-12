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
#   --no-systemd        Skip systemd service teardown
#   --remove-user       Remove the service user even if not installer-created
#   -y, --yes           Skip confirmation prompts
#

set -e

INSTALL_DIR="/opt/myfsio"
DATA_DIR="/var/lib/myfsio"
LOG_DIR="/var/log/myfsio"
SERVICE_USER="myfsio"
KEEP_DATA=false
KEEP_LOGS=false
SKIP_SYSTEMD=false
AUTO_YES=false
REMOVE_USER=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-data)    KEEP_DATA=true; shift ;;
        --keep-logs)    KEEP_LOGS=true; shift ;;
        --install-dir)  INSTALL_DIR="$2"; shift 2 ;;
        --data-dir)     DATA_DIR="$2"; shift 2 ;;
        --log-dir)      LOG_DIR="$2"; shift 2 ;;
        --user)         SERVICE_USER="$2"; shift 2 ;;
        --no-systemd)   SKIP_SYSTEMD=true; shift ;;
        --remove-user)  REMOVE_USER=true; shift ;;
        -y|--yes)       AUTO_YES=true; shift ;;
        -h|--help)      head -20 "$0" | tail -15; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

RESERVED_PATHS=(/bin /boot /dev /etc /home /lib /lib32 /lib64 /media /mnt /opt /proc /root /run /sbin /srv /sys /tmp /usr /var)

validate_target_path() {
    local flag="$1"
    local value="$2"
    local canonical
    local shown
    local reserved

    if [[ "$value" != /* ]]; then
        echo "  [ERROR] $flag must be an absolute path (got: '$value')"
        exit 1
    fi

    canonical=""
    if command -v realpath &>/dev/null; then
        canonical=$(realpath -m -- "$value" 2>/dev/null) || canonical=""
    fi
    if [[ -z "$canonical" ]]; then
        canonical="$value"
        case "$canonical/" in
            */./*|*/../*)
                echo "  [ERROR] $flag must not contain '.' or '..' path segments (got: '$value')"
                exit 1
                ;;
        esac
    fi
    while [[ "$canonical" == *//* ]]; do
        canonical="${canonical//\/\///}"
    done
    while [[ "$canonical" == */ && "$canonical" != "/" ]]; do
        canonical="${canonical%/}"
    done

    shown="'$value'"
    if [[ "$canonical" != "$value" ]]; then
        shown="'$value' -> '$canonical'"
    fi

    if [[ -z "$canonical" || "$canonical" == "/" ]]; then
        echo "  [ERROR] $flag must not be the filesystem root (got: $shown)"
        exit 1
    fi
    for reserved in "${RESERVED_PATHS[@]}"; do
        if [[ "$canonical" == "$reserved" ]]; then
            echo "  [ERROR] $flag must not be the system directory $reserved (got: $shown)"
            exit 1
        fi
    done

    CANONICAL_PATH="$canonical"
}

echo ""
echo "============================================================"
echo "               MyFSIO Uninstallation Script"
echo "============================================================"
echo ""
echo "Documentation: https://go.jzwsite.com/myfsio"
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

validate_target_path "--install-dir" "$INSTALL_DIR"
INSTALL_DIR="$CANONICAL_PATH"
validate_target_path "--data-dir" "$DATA_DIR"
DATA_DIR="$CANONICAL_PATH"
validate_target_path "--log-dir" "$LOG_DIR"
LOG_DIR="$CANONICAL_PATH"

MANIFEST_FILE="$INSTALL_DIR/.install-manifest"
SERVICE_USER_CREATED=false
if [[ -f "$MANIFEST_FILE" ]]; then
    MANIFEST_USER=""
    MANIFEST_CREATED=""
    while IFS='=' read -r manifest_key manifest_value; do
        case "$manifest_key" in
            SERVICE_USER)         MANIFEST_USER="$manifest_value" ;;
            SERVICE_USER_CREATED) MANIFEST_CREATED="$manifest_value" ;;
        esac
    done < "$MANIFEST_FILE"
    if [[ "$MANIFEST_USER" == "$SERVICE_USER" && "$MANIFEST_CREATED" == true ]]; then
        SERVICE_USER_CREATED=true
    fi
fi

if [[ "$SERVICE_USER_CREATED" == true || "$REMOVE_USER" == true ]]; then
    REMOVE_SERVICE_USER=true
else
    REMOVE_SERVICE_USER=false
fi

echo "------------------------------------------------------------"
echo "STEP 1: Review What Will Be Removed"
echo "------------------------------------------------------------"
echo ""
echo "The following items will be removed:"
echo ""
echo "  Install directory: $INSTALL_DIR"
if [[ "$KEEP_DATA" != true ]]; then
    echo "  Data directory:    $DATA_DIR"
    echo "                     [!] ALL DATA, IAM USERS, AND ENCRYPTION KEYS WILL BE DELETED!"
else
    echo "  Data directory:    $DATA_DIR (WILL BE KEPT)"
fi
if [[ "$KEEP_LOGS" != true ]]; then
    echo "  Log directory:     $LOG_DIR"
else
    echo "  Log directory:     $LOG_DIR (WILL BE KEPT)"
fi
echo "  Systemd service:   /etc/systemd/system/myfsio.service"
if [[ "$REMOVE_SERVICE_USER" == true ]]; then
    echo "  System user:       $SERVICE_USER"
else
    echo "  System user:       $SERVICE_USER (WILL BE KEPT)"
fi
echo ""

if [[ "$AUTO_YES" != true ]]; then
    echo "WARNING: This action cannot be undone!"
    echo ""
    read -p "Are you sure you want to uninstall MyFSIO? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "Uninstallation cancelled."
        exit 0
    fi
    
    if [[ "$KEEP_DATA" != true ]]; then
        echo ""
        read -p "This will DELETE ALL YOUR DATA. Type 'DELETE' to confirm: " CONFIRM
        if [[ "$CONFIRM" != "DELETE" ]]; then
            echo ""
            echo "Uninstallation cancelled."
            echo "Tip: Use --keep-data to preserve your data directory"
            exit 0
        fi
    fi
fi

if [[ "$SKIP_SYSTEMD" != true ]]; then
    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 2: Stopping Service"
    echo "------------------------------------------------------------"
    echo ""
    if systemctl is-active --quiet myfsio 2>/dev/null; then
        systemctl stop myfsio
        echo "  [OK] Stopped myfsio service"
    else
        echo "  [SKIP] Service not running"
    fi

    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 3: Disabling Service"
    echo "------------------------------------------------------------"
    echo ""
    if systemctl is-enabled --quiet myfsio 2>/dev/null; then
        systemctl disable myfsio
        echo "  [OK] Disabled myfsio service"
    else
        echo "  [SKIP] Service not enabled"
    fi

    echo ""
    echo "------------------------------------------------------------"
    echo "STEP 4: Removing Systemd Service File"
    echo "------------------------------------------------------------"
    echo ""
    if [[ -f /etc/systemd/system/myfsio.service ]]; then
        rm -f /etc/systemd/system/myfsio.service
        systemctl daemon-reload
        echo "  [OK] Removed /etc/systemd/system/myfsio.service"
        echo "  [OK] Reloaded systemd daemon"
    else
        echo "  [SKIP] Service file not found"
    fi
else
    echo ""
    echo "------------------------------------------------------------"
    echo "STEPS 2-4: Skipping Systemd Teardown (--no-systemd)"
    echo "------------------------------------------------------------"
    echo ""
    echo "  Stop any running myfsio process manually before continuing."
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 5: Removing Installation Directory"
echo "------------------------------------------------------------"
echo ""
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    echo "  [OK] Removed $INSTALL_DIR"
else
    echo "  [SKIP] Directory not found: $INSTALL_DIR"
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 6: Removing Data Directory"
echo "------------------------------------------------------------"
echo ""
if [[ "$KEEP_DATA" != true ]]; then
    if [[ -d "$DATA_DIR" ]]; then
        rm -rf "$DATA_DIR"
        echo "  [OK] Removed $DATA_DIR"
    else
        echo "  [SKIP] Directory not found: $DATA_DIR"
    fi
else
    echo "  [KEPT] Data preserved at: $DATA_DIR"
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 7: Removing Log Directory"
echo "------------------------------------------------------------"
echo ""
if [[ "$KEEP_LOGS" != true ]]; then
    if [[ -d "$LOG_DIR" ]]; then
        rm -rf "$LOG_DIR"
        echo "  [OK] Removed $LOG_DIR"
    else
        echo "  [SKIP] Directory not found: $LOG_DIR"
    fi
else
    echo "  [KEPT] Logs preserved at: $LOG_DIR"
fi

echo ""
echo "------------------------------------------------------------"
echo "STEP 8: Removing System User"
echo "------------------------------------------------------------"
echo ""
if id "$SERVICE_USER" &>/dev/null; then
    if [[ "$REMOVE_SERVICE_USER" == true ]]; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        echo "  [OK] Removed user '$SERVICE_USER'"
    else
        echo "  [SKIP] User '$SERVICE_USER' was not created by the installer - preserving"
        echo "         Use --remove-user to delete it anyway"
    fi
else
    echo "  [SKIP] User not found: $SERVICE_USER"
fi

echo ""
echo "============================================================"
echo "            Uninstallation Complete!"
echo "============================================================"
echo ""

if [[ "$KEEP_DATA" == true ]]; then
    echo "Your data has been preserved at: $DATA_DIR"
    echo ""
    echo "Preserved files include:"
    echo "  - All buckets and objects"
    echo "  - IAM configuration: $DATA_DIR/.myfsio.sys/config/iam.json (encrypted at rest)"
    echo "  - Bucket policies:   $DATA_DIR/.myfsio.sys/config/bucket_policies.json"
    echo "  - Secret key:        $DATA_DIR/.myfsio.sys/config/.secret"
    echo "  - Encryption keys:   $DATA_DIR/.myfsio.sys/keys/ (if encryption was enabled)"
    echo ""
    echo "NOTE: The IAM config is encrypted at rest and is unlocked by the .secret"
    echo "      file in the data directory. Keep that file intact for reinstallation."
    echo ""
    echo "To reinstall MyFSIO with existing data:"
    echo "  ./install.sh --binary ./myfsio --data-dir $DATA_DIR"
    echo ""
fi

if [[ "$KEEP_LOGS" == true ]]; then
    echo "Your logs have been preserved at: $LOG_DIR"
    echo ""
fi

echo "Thank you for using MyFSIO."
echo "Documentation: https://go.jzwsite.com/myfsio"
echo ""
echo "============================================================"
echo ""
