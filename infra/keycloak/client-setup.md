# Keycloak Client Setup

## Purpose

Configure Keycloak client for PEP (Policy Enforcement Point) authentication.

## Steps

1. **Access Keycloak Admin Console**

   - URL: `http://localhost:8080`
   - Username: `admin`
   - Password: (set during installation)

2. **Import Realm**

   ```bash
   # Import the UZTAF realm configuration
   /opt/keycloak/bin/kc.sh import --file /path/to/realm-export.json
   ```

3. **Create Client**

   - Realm: `uztaf`
   - Client ID: `pep-client`
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`

4. **Configure Client**

   - Valid Redirect URIs: `*` (configure appropriately for production)
   - Web Origins: `*`
   - Service Accounts Enabled: `On`
   - Authorization Enabled: `On`

5. **Get Client Secret**

   - Navigate to Credentials tab
   - Copy the Secret
   - Add to `.env` file: `KEYCLOAK_CLIENT_SECRET=<secret>`

6. **Create Roles**

   - admin
   - user
   - viewer

7. **Create Test User**
   - Username: `testuser`
   - Email: `testuser@example.com`
   - Password: Set temporary password
   - Assign roles as needed

## Verification

Test authentication:

```bash
curl -X POST http://localhost:8080/realms/uztaf/protocol/openid-connect/token \
  -d "client_id=pep-client" \
  -d "client_secret=<secret>" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=<password>"
```
