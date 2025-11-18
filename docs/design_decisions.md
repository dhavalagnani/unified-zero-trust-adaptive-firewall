# UZTAF Design Decisions

## Purpose

Document key architectural and implementation decisions for the Unified Zero-Trust Adaptive Firewall.

## Core Principles

### 1. Zero-Trust Architecture

**Decision:** Verify every request, trust nothing by default

**Rationale:**

- Modern threat landscape requires defense in depth
- Internal network compromises are common
- Micro-segmentation provides better security

**Trade-offs:**

- Added latency from authentication checks
- Increased complexity
- More operational overhead

### 2. Real-Time Correlation

**Decision:** Process security events in real-time with sliding time windows

**Rationale:**

- Attacks happen quickly, response must be immediate
- Historical analysis alone is insufficient
- Correlation across multiple sources improves detection

**Alternatives Considered:**

- Batch processing: Too slow for active threats
- Rule-based only: Misses novel attack patterns
- ML-only: Resource intensive, harder to explain

### 3. Distributed Enforcement

**Decision:** Deploy agents on each node rather than centralized firewall

**Rationale:**

- Scales horizontally
- No single point of failure
- Closer to traffic source
- Faster response time

**Trade-offs:**

- More components to manage
- Agent deployment complexity
- Consistency challenges

## Technology Choices

### FastAPI for PEP

**Why FastAPI:**

- High performance (async)
- Built-in OpenAPI documentation
- Type hints and validation
- Easy to test

**Alternatives:**

- Kong/NGINX+Lua: Less flexible
- Spring Gateway: Java overhead
- Custom Go service: Development time

### Keycloak for IAM

**Why Keycloak:**

- Industry standard OpenID Connect
- Feature-rich out of the box
- Good documentation
- No licensing costs

**Alternatives:**

- Auth0: Costs, vendor lock-in
- Custom OAuth2: Maintenance burden
- LDAP only: Insufficient for modern needs

### nftables for Enforcement

**Why nftables:**

- Modern Linux firewall
- Better performance than iptables
- Cleaner syntax
- Atomic rule updates

**Alternatives:**

- iptables: Legacy, less efficient
- eBPF/XDP: Too low-level, complex
- Application-level: Easier to bypass

### SQLite for Event Storage

**Why SQLite:**

- Embedded, no separate server
- Fast for read-heavy workloads
- ACID transactions
- Easy backup

**Alternatives:**

- PostgreSQL: Overkill for this use case
- MongoDB: Unnecessary complexity
- In-memory only: Data loss risk

### WebSockets for Agent Communication

**Why WebSockets:**

- Bidirectional real-time communication
- Lower latency than polling
- Efficient for rule distribution
- Built-in reconnection handling

**Alternatives:**

- gRPC: More overhead, bidirectional streaming similar
- REST polling: Too slow, inefficient
- Message queue (RabbitMQ): Additional infrastructure

## Design Patterns

### 1. Event-Driven Architecture

**Pattern:** Components communicate via events rather than direct calls

**Benefits:**

- Loose coupling
- Easy to add new event sources
- Scalable
- Resilient

### 2. Trie-Based Pattern Matching

**Pattern:** Use trie data structure for efficient sequence matching

**Benefits:**

- O(k) lookup time (k = pattern length)
- Memory efficient for large pattern sets
- Supports partial matching
- Easy to add/remove patterns

### 3. Rule Expiration

**Pattern:** All rules have TTL and expire automatically

**Benefits:**

- Prevents stale rules
- Adapts to changing threats
- Reduces false positives over time
- Self-cleaning system

### 4. Graceful Degradation

**Pattern:** System continues operating with reduced functionality if components fail

**Examples:**

- PEP works without correlation engine
- Agents cache rules locally
- Correlation continues without agents

## Security Decisions

### 1. JWT Token Validation

**Decision:** Validate signature, expiration, issuer, and audience

**Why:**

- Prevents token tampering
- Limits token lifetime
- Ensures token intended for this service

### 2. No Token Storage

**Decision:** PEP doesn't store tokens, validates on each request

**Why:**

- Stateless design (scales better)
- No session management needed
- Token revocation handled by expiration

**Trade-off:**

- Must validate every time (performance)
- No way to immediately revoke (until expiry)

### 3. Rule Priority System

**Decision:** Rules have priorities; higher priority = evaluated first

**Why:**

- Allows exceptions (e.g., whitelist before blacklist)
- More flexible than flat rule list
- Performance optimization (most common rules first)

### 4. Separate Credentials

**Decision:** Each component has its own credentials

**Why:**

- Principle of least privilege
- Easier to revoke individual access
- Better audit trail

## Scalability Decisions

### 1. Horizontal Scaling

**Decision:** Scale by adding more PEP/agent instances

**Why:**

- Cloud-native approach
- No single bottleneck
- Cost-effective

### 2. Stateless PEP

**Decision:** PEP instances share no state

**Why:**

- Easy to scale horizontally
- No sticky sessions needed
- Simple load balancing

### 3. Event Sharding

**Decision:** Correlation engine can shard events by source IP

**Why:**

- Parallel processing
- Scales with event volume
- Maintains temporal ordering per IP

## Operational Decisions

### 1. Systemd Services

**Decision:** Run components as systemd services

**Why:**

- Standard Linux service management
- Automatic restart
- Log integration (journald)
- Dependency management

### 2. Configuration in Environment Variables

**Decision:** Support both files and env vars

**Why:**

- 12-factor app compatibility
- Works with Docker/Kubernetes
- Easy secret management

### 3. Ansible for Deployment

**Decision:** Use Ansible for infrastructure deployment

**Why:**

- Agentless
- Idempotent
- Good for bare-metal and VMs
- Readable YAML playbooks

**Alternatives:**

- Terraform: Better for cloud resources
- Puppet/Chef: Need agents
- Custom scripts: Hard to maintain

## Future Considerations

### Machine Learning Integration

- Initially using rule-based correlation
- Can add ML models later for:
  - Anomaly detection
  - Attack classification
  - False positive reduction

### Multi-Tenancy

- Current design single-tenant
- Can extend with:
  - Realm isolation
  - Per-tenant rule sets
  - Separate databases

### Cloud Integration

- Designed for on-premises
- Can integrate with:
  - Cloud security groups
  - WAF services
  - Cloud-native firewalls
