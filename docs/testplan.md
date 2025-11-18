# UZTAF Test Plan

## Purpose

Comprehensive testing strategy for the Unified Zero-Trust Adaptive Firewall system.

## Test Categories

### 1. Unit Tests

**PEP Authentication:**

- JWT token validation
- User info extraction
- Role-based access control
- Token expiration handling

**Correlation Engine:**

- Event processing
- Pattern matching (trie)
- Rule generation
- Score calculation

**Agent:**

- nftables rule application
- WebSocket communication
- Rule expiration
- Log monitoring

### 2. Integration Tests

**Authentication Flow:**

1. User requests access
2. PEP validates with Keycloak
3. Request proxied to backend
4. Response returned

**Quarantine Flow:**

1. IDS detects suspicious activity
2. Events sent to correlation engine
3. Correlation triggers rule generation
4. Rules distributed to agents
5. Agents apply nftables rules
6. Traffic blocked

### 3. End-to-End Tests

**Scenario 1: Port Scan Detection**

```bash
# Simulate port scan
nmap -p- target-host

# Verify:
# - Zeek/Suricata detect scan
# - Correlation engine generates rules
# - Agent blocks scanner IP
# - Access denied
```

**Scenario 2: Brute Force Attack**

```bash
# Simulate SSH brute force
hydra -l user -P passwords.txt ssh://target

# Verify:
# - Failed login attempts logged
# - Correlation detects pattern
# - IP quarantined
```

**Scenario 3: False Positive Handling**

```bash
# Trigger false positive
# Manually revoke rule
# Verify traffic restored
```

### 4. Performance Tests

**Load Testing:**

- PEP: 1000 req/sec
- Correlation: 10000 events/sec
- Agent: Rule application latency < 100ms

**Stress Testing:**

- Sustained load for 1 hour
- Memory leak detection
- CPU usage monitoring

### 5. Security Tests

**Authentication:**

- Expired token rejection
- Invalid signature detection
- Missing token handling

**Authorization:**

- Role enforcement
- Path-based policies
- Cross-user access prevention

**Rule Injection:**

- Malformed rule handling
- SQL injection attempts
- Command injection prevention

## Test Execution

### Running Unit Tests

```bash
# PEP tests
cd src/pep
source venv/bin/activate
pytest tests/ -v --cov

# Correlation tests
cd src/correlation
source venv/bin/activate
pytest tests/ -v --cov

# Agent tests
cd src/agent
source venv/bin/activate
pytest tests/ -v
```

### Running Integration Tests

```bash
cd tests/integration
bash test_quarantine_flow.sh
bash test_rule_distribution.sh
```

### Performance Testing

```bash
# Load test PEP
ab -n 10000 -c 100 http://pep-server:8000/

# Monitor correlation engine
watch -n 1 'curl -s http://correlation:5000/stats | jq .'
```

## Test Data

### Mock Users

- admin / changeme (admin role)
- user1 / password (user role)
- viewer / password (viewer role)

### Mock Events

See `scripts/suricata_test_alert.sh`

### Test IPs

- Attacker: 192.168.100.100
- Victim: 10.0.1.50
- Allowed: 192.168.1.0/24

## Success Criteria

**Functional:**

- All unit tests pass
- Integration scenarios complete successfully
- End-to-end flows work as expected

**Performance:**

- PEP latency < 50ms (p95)
- Rule application < 100ms
- No memory leaks after 1 hour

**Security:**

- No authentication bypasses
- Authorization correctly enforced
- Injection attacks blocked

## Regression Testing

Run full test suite before:

- Merging PRs
- Deploying to production
- Major version updates

## Continuous Integration

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run unit tests
        run: |
          cd src/pep && pytest
          cd src/correlation && pytest
      - name: Run integration tests
        run: |
          bash tests/integration/test_quarantine_flow.sh
```

## Test Coverage Goals

- Unit test coverage: > 80%
- Integration test coverage: > 60%
- Critical paths: 100%
