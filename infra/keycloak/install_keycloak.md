# Installing Keycloak as a Systemd Service

## Purpose

Install and configure Keycloak for UZTAF without Docker.

## Prerequisites

- Java 17 or later
- PostgreSQL (optional, for production)
- sudo access

## Installation Steps

### 1. Download Keycloak

```bash
cd /opt
sudo wget https://github.com/keycloak/keycloak/releases/download/23.0.0/keycloak-23.0.0.tar.gz
sudo tar -xzf keycloak-23.0.0.tar.gz
sudo mv keycloak-23.0.0 keycloak
```

### 2. Create Keycloak User

```bash
sudo useradd -r -s /bin/false keycloak
sudo chown -R keycloak:keycloak /opt/keycloak
```

### 3. Configure Keycloak

```bash
cd /opt/keycloak
sudo -u keycloak bin/kc.sh build
```

### 4. Set Admin Credentials

```bash
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=changeme
```

### 5. Create Systemd Service

```bash
sudo tee /etc/systemd/system/keycloak.service <<EOF
[Unit]
Description=Keycloak Identity Provider
After=network.target

[Service]
Type=simple
User=keycloak
Group=keycloak
WorkingDirectory=/opt/keycloak
Environment="KEYCLOAK_ADMIN=admin"
Environment="KEYCLOAK_ADMIN_PASSWORD=changeme"
ExecStart=/opt/keycloak/bin/kc.sh start-dev --http-port=8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### 6. Start Keycloak

```bash
sudo systemctl daemon-reload
sudo systemctl enable keycloak
sudo systemctl start keycloak
```

### 7. Verify Installation

```bash
sudo systemctl status keycloak
curl http://localhost:8080
```

### 8. Import UZTAF Realm

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh import \
  --file /path/to/realm-export.json
```

## Production Configuration

For production, configure:

- External PostgreSQL database
- TLS/SSL certificates
- Reverse proxy (nginx)
- Clustering (if needed)

See Keycloak documentation for production deployment guidelines.
