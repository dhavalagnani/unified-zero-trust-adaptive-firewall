# UZTAF Runbook

## Purpose

Operational procedures for managing the Unified Zero-Trust Adaptive Firewall system.

## System Components

1. **PEP (Policy Enforcement Point)** - Port 8000
2. **Keycloak** - Port 8080
3. **Correlation Engine** - Port 5000
4. **Agents** - Distributed across network nodes
5. **Zeek/Suricata** - Network monitoring

## Starting the System

### Full System Startup

```bash
cd /path/to/uztaf
sudo ./bootstrap.sh
```

### Individual Components

**Start Keycloak:**

```bash
sudo systemctl start keycloak
```

**Start PEP:**

```bash
sudo systemctl start pep
```

**Start Correlation Engine:**

```bash
sudo systemctl start correlation
```

**Start Agent:**

```bash
sudo systemctl start uztaf-agent
```

## Monitoring

### Check Service Status

```bash
sudo systemctl status pep correlation uztaf-agent
```

### View Logs

```bash
# PEP logs
sudo journalctl -u pep -f

# Correlation engine logs
sudo journalctl -u correlation -f

# Agent logs
sudo journalctl -u uztaf-agent -f
```

### Check Active Rules

```bash
sudo nft list ruleset | grep uztaf
```

## Common Operations

### Adding a User

1. Log into Keycloak admin console
2. Navigate to Users
3. Add user with appropriate roles

### Manually Block an IP

```bash
sudo nft add rule inet filter uztaf_quarantine ip saddr <IP> drop
```

### Revoke a Rule

Query correlation engine API or wait for expiration

### View Correlations

```bash
sqlite3 /var/lib/uztaf/correlation.db "SELECT * FROM correlations ORDER BY created_at DESC LIMIT 10"
```

## Troubleshooting

### PEP Not Starting

- Check Keycloak is running
- Verify .env configuration
- Check port 8000 availability

### Agent Not Connecting

- Verify WebSocket URL in config
- Check network connectivity to correlation server
- Review agent logs

### Rules Not Applying

- Check agent has sudo permissions for nft
- Verify nftables is installed
- Check agent service status

### False Positives

1. Identify the rule ID
2. Revoke via correlation engine API
3. Adjust correlation thresholds

## Maintenance

### Database Backup

```bash
cp /var/lib/uztaf/correlation.db /backup/correlation-$(date +%Y%m%d).db
```

### Log Rotation

Logs rotate automatically via systemd. Manual rotation:

```bash
sudo journalctl --vacuum-time=7d
```

### Update Components

```bash
cd /path/to/uztaf
git pull
sudo systemctl restart pep correlation uztaf-agent
```

## Emergency Procedures

### System Under Attack

1. Monitor correlation engine output
2. Verify rules are being applied
3. Manually block IPs if needed
4. Review and adjust thresholds

### Complete Shutdown

```bash
sudo systemctl stop uztaf-agent correlation pep keycloak
```

### Disable All Dynamic Rules

```bash
sudo nft flush chain inet filter uztaf_quarantine
```

## Performance Tuning

### PEP Workers

Edit `/etc/systemd/system/pep.service`:

```
Environment="PEP_WORKERS=8"
```

### Correlation Thresholds

Edit configuration or use API to adjust:

- correlation_threshold
- time_window
- anomaly_threshold

## Backup and Recovery

### Full Backup

```bash
tar -czf uztaf-backup-$(date +%Y%m%d).tar.gz \
  /opt/uztaf \
  /etc/uztaf \
  /var/lib/uztaf \
  /etc/systemd/system/*uztaf* \
  /etc/systemd/system/pep.service \
  /etc/systemd/system/correlation.service
```

### Recovery

```bash
tar -xzf uztaf-backup-YYYYMMDD.tar.gz -C /
sudo systemctl daemon-reload
sudo systemctl restart pep correlation uztaf-agent
```
