#!/bin/bash
#
# scripts/rotate-keys.sh
#
# Purpose: Rotate JWT signing keys and client secrets
# Context: Security best practice to periodically rotate cryptographic keys

set -e

echo "=== UZTAF Key Rotation ==="

BACKUP_DIR="./backups/keys-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "1. Backing up current keys..."
cp .env "$BACKUP_DIR/env.backup"
cp certs/* "$BACKUP_DIR/" 2>/dev/null || true
echo "✓ Backup created: $BACKUP_DIR"

echo "2. Generating new client secret..."
NEW_SECRET=$(openssl rand -hex 32)
echo "New client secret: $NEW_SECRET"

echo "3. Update Keycloak client secret..."
echo "Manual step: Update client secret in Keycloak admin console"
echo "  - Realm: uztaf"
echo "  - Client: pep-client"
echo "  - Credentials tab"

echo "4. Update .env file..."
sed -i.bak "s/KEYCLOAK_CLIENT_SECRET=.*/KEYCLOAK_CLIENT_SECRET=$NEW_SECRET/" .env

echo "5. Restart services..."
sudo systemctl restart pep correlation

echo "6. Verify services started successfully..."
sleep 5
sudo systemctl status pep correlation --no-pager

echo "✓ Key rotation complete"
echo ""
echo "Next steps:"
echo "  1. Update client secret in Keycloak"
echo "  2. Test authentication"
echo "  3. Monitor logs for issues"
echo "  4. Backup is at: $BACKUP_DIR"
