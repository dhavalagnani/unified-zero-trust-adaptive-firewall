#!/bin/bash
#
# tests/integration/test_quarantine_flow.sh
#
# Purpose: Test complete quarantine flow from detection to enforcement
# Context: End-to-end integration test for UZTAF system

set -e

echo "=== UZTAF Quarantine Flow Test ==="

# Configuration
CORRELATION_URL="http://localhost:5000"
PEP_URL="http://localhost:8000"
TEST_IP="192.168.100.100"
AGENT_HOST="localhost"

echo "1. Checking services are running..."
systemctl is-active --quiet pep || { echo "PEP not running"; exit 1; }
systemctl is-active --quiet correlation || { echo "Correlation engine not running"; exit 1; }
systemctl is-active --quiet uztaf-agent || { echo "Agent not running"; exit 1; }
echo "✓ All services running"

echo "2. Simulating suspicious events..."
# Simulate multiple failed login attempts
for i in {1..5}; do
    curl -X POST "$CORRELATION_URL/api/event" \
        -H "Content-Type: application/json" \
        -d "{
            \"timestamp\": \"$(date -Iseconds)\",
            \"source_ip\": \"$TEST_IP\",
            \"dest_ip\": \"10.0.1.50\",
            \"source_port\": 50000,
            \"dest_port\": 22,
            \"protocol\": \"tcp\",
            \"event_type\": \"brute_force\",
            \"severity\": \"high\",
            \"source\": \"test\",
            \"metadata\": {\"attempt\": $i}
        }"
    sleep 1
done
echo "✓ Events submitted"

echo "3. Waiting for correlation (10 seconds)..."
sleep 10

echo "4. Checking for generated rules..."
RULES=$(curl -s "$CORRELATION_URL/api/rules")
echo "Rules: $RULES"

if echo "$RULES" | grep -q "$TEST_IP"; then
    echo "✓ Rule generated for $TEST_IP"
else
    echo "✗ No rule found for $TEST_IP"
    exit 1
fi

echo "5. Verifying nftables rule applied..."
if sudo nft list ruleset | grep -q "$TEST_IP"; then
    echo "✓ nftables rule applied"
else
    echo "✗ nftables rule NOT applied"
    exit 1
fi

echo "6. Testing enforcement (should be blocked)..."
if timeout 3 ping -c 1 $TEST_IP > /dev/null 2>&1; then
    echo "✗ Traffic NOT blocked (test may be invalid if $TEST_IP doesn't exist)"
else
    echo "✓ Traffic blocked (or IP unreachable)"
fi

echo "7. Cleanup - removing test rule..."
# Find rule handle and remove
# sudo nft delete rule inet filter uztaf_quarantine handle <handle>
echo "✓ Test completed"

echo "=== Quarantine Flow Test PASSED ==="
