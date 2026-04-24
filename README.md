# Keycloak → Kong → OPA Data-Masking Demo

A self-contained Docker Compose demo showing end-to-end PII masking enforced at the API gateway.

## Architecture

```
Browser
  │
  │  OIDC login / JWT
  ▼
Website (Flask :3000)
  │
  │  Bearer <JWT>
  ▼
Kong API Gateway (:8000)          ← DB-less, serverless Lua plugins
  │  1. Introspect JWT ──────────► Keycloak (:8080)
  │  2. Policy check ────────────► OPA (:8181)  →  allow / deny / masked_fields
  │  3. Fetch raw data ──────────► CRM Mock (:5001)
  │  4. Mask PII fields in response body (Lua post-function)
  │
  └──► masked JSON back to Website → rendered in browser
```

### Role → masking policy (OPA)

| Role       | name   | msisdn | email  |
|------------|--------|--------|--------|
| agent      | masked | masked | masked |
| supervisor | clear  | masked | clear  |
| admin      | clear  | clear  | clear  |

## Quick start

```bash
docker compose up --build
```

First boot takes ~2 min for Keycloak to initialise.

Open **http://localhost:3000** and log in with one of:

| Username    | Password  | Role       |
|-------------|-----------|------------|
| agent1      | agent123  | agent      |
| supervisor1 | super123  | supervisor |
| admin1      | admin123  | admin      |

Then search for any of `C001`, `C002`, `C003`, `C004`.

## Component map

| Path | Purpose |
|------|---------|
| `keycloak/realm-config.json` | Auto-imported realm (users, clients, roles) |
| `opa/policy.rego` | Access-control + masking-field rules |
| `kong/kong.yml` | DB-less Kong config (routes + plugins) |
| `kong/plugins/auth-opa.lua` | Kong pre-function: JWT introspection + OPA call |
| `kong/plugins/masking.lua` | Kong post-function: response body masking |
| `crm-mock/` | Flask mock CRM with raw customer data |
| `website/` | Flask portal with Keycloak OIDC login |

## Manual API test

```bash
# Get a token (direct grant – needs directAccessGrantsEnabled in dev)
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=agent1&password=agent123&grant_type=password" \
  | jq -r .access_token)

# Call Kong – response will have masked fields
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/customer/C001 | jq
```
