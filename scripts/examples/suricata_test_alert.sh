#!/bin/bash
#
# scripts/examples/suricata_test_alert.sh
#
# Purpose: Generate test alert in Suricata for testing correlation engine
# Context: Sends crafted packets that trigger Suricata rules

set -e

TARGET_IP="10.0.1.50"
ATTACKER_IP="192.168.100.100"

echo "Generating Suricata test alerts..."

# Test 1: Port scan detection
echo "1. Simulating port scan..."
nmap -sS -T4 -p 1-100 "$TARGET_IP" 2>&1 | head -5

# Test 2: HTTP attack pattern
echo "2. Simulating web attack..."
curl "http://$TARGET_IP/test.php?cmd=whoami" 2>/dev/null || true
curl "http://$TARGET_IP/../../../../etc/passwd" 2>/dev/null || true

# Test 3: SSH brute force (if you have hydra)
# echo "3. Simulating SSH brute force..."
# hydra -l testuser -P /usr/share/wordlists/rockyou.txt \
#     ssh://$TARGET_IP -t 4 2>&1 | head -5 || true

# Test 4: DNS tunneling pattern
echo "4. Simulating DNS tunneling..."
dig @$TARGET_IP "$(head -c 60 /dev/urandom | base64 | tr -d '\n').example.com" || true

echo ""
echo "Test alerts generated. Check Suricata eve.json:"
echo "  tail -f /var/log/suricata/eve.json"
echo ""
echo "Check correlation engine:"
echo "  curl http://localhost:5000/api/stats"
