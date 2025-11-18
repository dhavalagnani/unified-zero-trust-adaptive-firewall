#!/bin/bash
#
# scripts/gen-certs.sh
#
# Purpose: Generate self-signed certificates for UZTAF components
# Context: Creates TLS certificates for secure communication between components

set -e

CERT_DIR="./certs"
mkdir -p "$CERT_DIR"

echo "Generating certificates for UZTAF..."

# Generate CA key and certificate
openssl genrsa -out "$CERT_DIR/ca.key" 4096

openssl req -new -x509 -days 365 -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=UZTAF/CN=UZTAF-CA"

# Generate server key
openssl genrsa -out "$CERT_DIR/server.key" 2048

# Generate server certificate signing request
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=UZTAF/CN=uztaf-server"

# Sign server certificate with CA
openssl x509 -req -days 365 \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt"

# Set appropriate permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "Certificates generated in $CERT_DIR/"
echo "  - ca.crt: Certificate Authority"
echo "  - server.crt/key: Server certificate"
echo ""
echo "For production, use certificates from a trusted CA."
