# UZTAF Project Summary

## Overview

Unified Zero-Trust Adaptive Firewall (UZTAF) is an intelligent security system that combines Zero-Trust authentication with real-time threat correlation and automated firewall enforcement.

## Key Features

### 1. Zero-Trust Policy Enforcement

- Every request requires authentication (Keycloak/OAuth2)
- Fine-grained authorization policies
- No implicit trust based on network location

### 2. Real-Time Threat Correlation

- Ingests events from Zeek, Suricata, and other sources
- Correlates events using temporal and behavioral patterns
- Calculates threat confidence scores
- Generates dynamic firewall rules

### 3. Distributed Enforcement

- Lightweight agents on each network node
- Apply nftables rules automatically
- WebSocket communication for real-time updates
- Rule expiration and automatic cleanup

### 4. Adaptive Response

- Rules generated based on threat severity
- Automatic quarantine of malicious IPs
- False positive handling
- Performance-optimized enforcement

## Architecture Components

**PEP (Policy Enforcement Point):**

- FastAPI reverse proxy
- JWT token validation
- Request logging and auditing
- Backend service proxying

**Correlation Engine:**

- Event ingestion from multiple sources
- Trie-based pattern matching
- Anomaly scoring algorithm
- Rule generation and distribution

**Enforcement Agents:**

- nftables firewall management
- WebSocket client for rules
- Local log monitoring
- Heartbeat and health reporting

**Identity Management:**

- Keycloak for authentication
- Role-based access control
- OpenID Connect / OAuth2
- User and group management

## Quick Start

```bash
# Clone repository
git clone <repo-url>
cd unified-zero-trust-adaptive-firewall

# Copy and configure environment
cp .env.example .env
# Edit .env with your configuration

# Run bootstrap script
sudo bash bootstrap.sh

# Access PEP
curl -H "Authorization: Bearer <token>" http://localhost:8000/
```

## Use Cases

**1. Enterprise Network Security**

- Protect internal applications
- Enforce identity-based access
- Detect and block lateral movement

**2. Cloud Infrastructure**

- Secure microservices
- Dynamic security groups
- Compliance and audit logging

**3. Critical Infrastructure**

- Industrial control systems
- SCADA network protection
- Real-time threat response

**4. Multi-Tenant Environments**

- Tenant isolation
- Per-tenant security policies
- Centralized monitoring

## Technology Stack

- **Language:** Python 3.9+
- **Web Framework:** FastAPI
- **Authentication:** Keycloak
- **Firewall:** nftables
- **IDS/IPS:** Zeek, Suricata
- **Communication:** WebSockets
- **Storage:** SQLite
- **Deployment:** Ansible, systemd
- **Infrastructure:** Terraform (optional)

## Project Structure

```
├── src/
│   ├── pep/              # Policy Enforcement Point
│   ├── correlation/      # Correlation Engine
│   └── agent/            # Enforcement Agents
├── infra/
│   ├── ansible/          # Deployment playbooks
│   ├── terraform/        # Infrastructure as code
│   └── keycloak/         # Identity management config
├── docs/                 # Documentation
├── tests/                # Integration tests
└── scripts/              # Utility scripts
```

## Documentation

- **Architecture:** `docs/architecture.puml`
- **Runbook:** `docs/runbook.md`
- **Test Plan:** `docs/testplan.md`
- **Design Decisions:** `docs/design_decisions.md`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Testing

```bash
# Unit tests
cd src/pep && pytest tests/
cd src/correlation && pytest tests/

# Integration tests
cd tests/integration
bash test_quarantine_flow.sh
bash test_rule_distribution.sh
```

## Performance

- **PEP Throughput:** 1000+ req/sec per worker
- **Rule Application:** < 100ms latency
- **Event Processing:** 10,000+ events/sec
- **Memory Footprint:** < 200MB per component

## Security Considerations

- Keep Keycloak updated
- Rotate secrets regularly
- Monitor for false positives
- Review correlation thresholds
- Audit access logs regularly

## Troubleshooting

See `docs/runbook.md` for common issues and solutions.

## License

MIT License - See LICENSE file

## Support

- Documentation: `docs/`
- Issues: GitHub Issues
- Discussions: GitHub Discussions

## Roadmap

**v1.1:**

- Machine learning integration
- Threat intelligence feeds
- Enhanced visualization dashboard

**v2.0:**

- Multi-tenancy support
- Cloud provider integrations
- Advanced analytics

## Credits

Developed as part of the Zero-Trust Network Security initiative.

## References

- Zero Trust Architecture: NIST SP 800-207
- OpenID Connect: https://openid.net/connect/
- nftables: https://netfilter.org/projects/nftables/
- Zeek: https://zeek.org/
- Suricata: https://suricata.io/
