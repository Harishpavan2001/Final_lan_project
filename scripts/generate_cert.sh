#!/bin/bash

# Resolve certificate storage directory path relative to script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../nginx/certs"

# Ensure target directory exists
mkdir -p "$CERT_DIR"

echo "Generating self-signed SSL/TLS certificates..."

# Generate 2048-bit RSA private key and self-signed certificate valid for 365 days
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -subj "/C=IN/ST=TamilNadu/L=Chennai/O=NPTEL/OU=NetworkSecurity/CN=localhost"

if [ $? -eq 0 ]; then
    echo "SSL Certificate successfully generated:"
    echo "  Private Key: $CERT_DIR/server.key"
    echo "  Certificate: $CERT_DIR/server.crt"
    chmod 600 "$CERT_DIR/server.key"
    chmod 644 "$CERT_DIR/server.crt"
else
    echo "Error generating SSL certificate via OpenSSL."
    exit 1
fi
