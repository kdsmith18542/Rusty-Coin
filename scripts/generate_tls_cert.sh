#!/bin/bash

# Generate TLS certificates for Rusty Coin RPC server
# This script generates self-signed certificates for development and testing

set -e

CERT_DIR="./certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
DAYS=365

echo "🔐 Generating TLS certificates for Rusty Coin RPC server..."

# Create certificates directory
mkdir -p "$CERT_DIR"

# Generate private key
echo "📝 Generating private key..."
openssl genrsa -out "$KEY_FILE" 2048

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key "$KEY_FILE" -out "$CERT_DIR/server.csr" -subj "/C=US/ST=State/L=City/O=RustyCoin/OU=Development/CN=localhost"

# Generate self-signed certificate
echo "📝 Generating self-signed certificate..."
openssl x509 -req -in "$CERT_DIR/server.csr" -signkey "$KEY_FILE" -out "$CERT_FILE" -days "$DAYS"

# Set appropriate permissions
chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

# Clean up CSR file
rm "$CERT_DIR/server.csr"

echo "✅ TLS certificates generated successfully!"
echo "📁 Certificate: $CERT_FILE"
echo "🔑 Private Key: $KEY_FILE"
echo "⏰ Valid for: $DAYS days"
echo ""
echo "🚀 To start RPC server with HTTPS:"
echo "   rusty-rpc --https --cert $CERT_FILE --key $KEY_FILE"
echo ""
echo "⚠️  WARNING: These are self-signed certificates for development only!"
echo "   For production, use certificates from a trusted Certificate Authority."
