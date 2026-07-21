#!/bin/sh

# Stop script execution on errors
set -e

# Default to production if environment is unset
ENV_PROFILE=${FLASK_ENV:-production}

echo "[BOOT] Booting container entrypoint..."
echo "[BOOT] Environment target: $ENV_PROFILE"

# Initialize database schema
python database/init_db.py "$ENV_PROFILE"

# Start application server via Gunicorn wsgi container
echo "[BOOT] Launching gunicorn application server..."
exec gunicorn --bind 0.0.0.0:5000 \
              --workers 4 \
              --threads 2 \
              --timeout 60 \
              "app:create_app(config_name='$ENV_PROFILE')"
