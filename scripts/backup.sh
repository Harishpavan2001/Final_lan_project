#!/bin/bash

# Resolve base directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$SCRIPT_DIR/.."
BACKUP_DIR="$BASE_DIR/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Create target backup folder
mkdir -p "$BACKUP_DIR"

echo "Starting gateway configuration and database backup..."

# Backup database
DB_FILE="$BASE_DIR/database/app.db"
if [ -f "$DB_FILE" ]; then
    cp "$DB_FILE" "$BACKUP_DIR/app_db_$TIMESTAMP.db"
    echo "  [DB] Backed up database schema & records."
else
    echo "  [DB] Skipping database (file not found)."
fi

# Backup whitelist
WL_FILE="$BASE_DIR/whitelist/whitelist.json"
if [ -f "$WL_FILE" ]; then
    cp "$WL_FILE" "$BACKUP_DIR/whitelist_$TIMESTAMP.json"
    echo "  [WL] Backed up IP whitelist configuration."
else
    echo "  [WL] Skipping whitelist config (file not found)."
fi

# Keep only the last 10 backups to prevent disk depletion
cd "$BACKUP_DIR" && ls -t | tail -n +21 | xargs rm -rf 2>/dev/null

echo "Backup execution finished successfully. Target: $BACKUP_DIR"
