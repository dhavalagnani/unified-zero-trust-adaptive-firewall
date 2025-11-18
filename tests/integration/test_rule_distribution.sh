#!/bin/bash
#
# tests/integration/test_rule_distribution.sh
#
# Purpose: Test rule distribution from correlation engine to agents
# Context: Verify WebSocket communication and rule synchronization

set -e

echo "=== UZTAF Rule Distribution Test ==="

CORRELATION_URL="http://localhost:5000"

echo "1. Checking correlation engine is running..."
if ! curl -sf "$CORRELATION_URL/health" > /dev/null; then
    echo "✗ Correlation engine not responding"
    exit 1
fi
echo "✓ Correlation engine healthy"

echo "2. Checking agents are connected..."
STATS=$(curl -s "$CORRELATION_URL/api/stats")
AGENT_COUNT=$(echo "$STATS" | jq -r '.connected_agents')

if [ "$AGENT_COUNT" -eq 0 ]; then
    echo "✗ No agents connected"
    exit 1
fi
echo "✓ $AGENT_COUNT agent(s) connected"

echo "3. Generating test rule..."
RULE_ID=$(uuidgen)
curl -X POST "$CORRELATION_URL/api/rule" \
    -H "Content-Type: application/json" \
    -d "{
        \"rule_id\": \"$RULE_ID\",
        \"action\": \"block\",
        \"source_ip\": \"192.168.99.99\",
        \"protocol\": \"all\",
        \"priority\": 10
    }"

echo "4. Waiting for rule distribution (5 seconds)..."
sleep 5

echo "5. Verifying rule on agent..."
if sudo nft list ruleset | grep -q "192.168.99.99"; then
    echo "✓ Rule distributed and applied"
else
    echo "✗ Rule NOT found on agent"
    exit 1
fi

echo "6. Revoking rule..."
curl -X DELETE "$CORRELATION_URL/api/rule/$RULE_ID"

echo "7. Waiting for revocation (5 seconds)..."
sleep 5

echo "8. Verifying rule removed..."
if sudo nft list ruleset | grep -q "192.168.99.99"; then
    echo "✗ Rule still present after revocation"
    exit 1
else
    echo "✓ Rule successfully removed"
fi

echo "=== Rule Distribution Test PASSED ==="
