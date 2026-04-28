# Data Masking Demo — Keycloak · Kong · OPA · Admin GUI

A self-contained Docker Compose stack demonstrating role-based PII masking
enforced at the API gateway, with a live admin console for policy management.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Browser                                                            │
│    │  1. OIDC login (auth code flow)                               │
│    ▼                                                                │
│  Website — Flask :3000                                              │
│    │  2. Bearer <JWT> on every CRM request                         │
│    ▼                                                                │
│  Kong API Gateway :8000  (DB-less, Lua serverless plugins)         │
│    │  3. Decode JWT payload locally — extract role from            │
│    │     realm_access.roles  (no Keycloak call per request)        │
│    │  4. Call OPA with role + customer_id + path ──► OPA :8181     │
│    │        ◄── allow/deny  +  masked_fields  +  is_vip            │
│    │  5. If is_vip: enforce X-Access-Reference header              │
│    │     fire real-time VIP alert to Log Dashboard                 │
│    │  6. Forward request ──────────────────────► CRM Mock :5000    │
│    │        ◄── raw customer JSON                                   │
│    │  7. Mask configured PII fields in response body (Lua)         │
│    │  8. Audit log ─────────────────────────────► Log Dashboard    │
│    ▼                                                                │
│  Masked JSON → rendered in browser                                 │
│                                                                     │
│  Admin GUI :8888  ──── manages ────► OPA data API                  │
│    (VIP list + role-field masking matrix, persisted in SQLite)     │
└─────────────────────────────────────────────────────────────────────┘
```

### Key design decisions

| Decision | Reason |
|---|---|
| JWT decoded locally in Kong | No per-request Keycloak call — lower latency, no auth service dependency on hot path |
| OPA for masking decisions | Policy as code, live updates via admin GUI without gateway restart |
| Admin service as OPA data source | Masking rules and VIP list are operational config, not code — owned by ops team |
| CRM port not exposed | All access to CRM data must pass through Kong enforcement |

---

## Data classification

Fields are classified into two sensitivity levels. OPA returns the list of
fields to mask; Kong applies the appropriate masking function to each.

### L1 — Direct identifiers

| Field | Masking applied |
|---|---|
| `name` | First letter of each word kept, rest starred — `A*** b** A*******` |
| `msisdn` | Country prefix kept, last 2 digits kept — `+6012****89` |
| `email` | First and last char of local part kept — `a*****d@gmail.com` |
| `national_id` | First 2 digits kept — `85************` |
| `address` | Fully redacted — `*** (redacted)` |

### L2 — Linkable / profiling data

| Field | Masking applied |
|---|---|
| `last_call_duration` | Fully redacted — `***` |
| `data_roaming_gb` | Fully redacted — `***` |
| `last_location` | Fully redacted — `***` |

---

## Role-based masking policy

Masking rules are live-configurable via the Admin GUI. The defaults are:

| Field | Classification | agent | supervisor | vip\_agent | admin |
|---|---|:---:|:---:|:---:|:---:|
| name | L1 | masked | clear | clear | clear |
| msisdn | L1 | masked | masked | clear | clear |
| email | L1 | masked | clear | clear | clear |
| national\_id | L1 | masked | masked | clear | clear |
| address | L1 | masked | clear | clear | clear |
| last\_call\_duration | L2 | masked | clear | clear | clear |
| data\_roaming\_gb | L2 | masked | clear | clear | clear |
| last\_location | L2 | masked | clear | clear | clear |

---

## VIP customer controls

Customers `C001` and `C004` are flagged as VIP. Stronger controls apply:

- **agent** and **supervisor** roles receive `403 Access Denied` — cannot access VIP records at all
- **vip\_agent** and **admin** must supply an `X-Access-Reference` header (ticket / case number) on every request
- A real-time alert event is fired to the Log Dashboard immediately on every VIP access
- Every VIP access is recorded in the audit log with username, role, reference, and timestamp
- The VIP list is managed in the Admin GUI and takes effect on the next request — no restart needed

---

## Services

| Service | URL | Purpose |
|---|---|---|
| Website | http://localhost:3000 | Agent-facing CRM portal |
| Keycloak | http://localhost:8080 | Identity provider (OIDC / JWT issuer) |
| Kong Gateway | http://localhost:8000 | API gateway — JWT decode, OPA enforcement, masking |
| Kong Admin | http://localhost:8001 | Kong admin API (internal) |
| OPA | http://localhost:8181 | Policy engine |
| Admin GUI | http://localhost:8888 | Live policy configuration console |
| Log Dashboard | http://localhost:9000 | Real-time audit log viewer |
| CRM Mock | internal only | Raw customer data — not exposed externally |

---

## Quick start

```bash
docker compose up --build
```

First boot takes **2–3 minutes** — Keycloak must finish importing the `demo`
realm before Kong starts. The healthcheck waits for `/realms/demo` to respond.

Once all containers are healthy, open **http://localhost:3000**.

---

## Demo users

| Username | Password | Role | Can access VIP? |
|---|---|---|---|
| `agent1` | `agent123` | agent | No — 403 |
| `supervisor1` | `super123` | supervisor | No — 403 |
| `vip1` | `vip123` | vip\_agent | Yes — with access reference |
| `admin1` | `admin123` | admin | Yes — with access reference |

---

## Test customers

| ID | Name | VIP | Notes |
|---|---|---|---|
| C001 | Ahmad bin Abdullah | Yes | VIP — requires access reference |
| C002 | Siti Nurhaliza binti Tarudin | No | Standard access |
| C003 | Rajesh Kumar Sharma | No | Suspended account |
| C004 | Mei Ling Tan | Yes | VIP — requires access reference |

---

## Admin GUI

Open **http://localhost:8888** and log in with `admin / admin123`.

| Page | What you can do |
|---|---|
| Dashboard | Overview of active masking rules, VIP list, OPA sync status |
| VIP Customers | Add or remove VIP customer IDs — syncs to OPA immediately |
| Masking Rules | Checkbox matrix of role × field — save pushes live to OPA |
| Sync OPA button | Force re-push of all config (use after OPA container restart) |
| `/api/config` | JSON view of the exact payload currently in OPA |

Changes take effect on the **next request** — no gateway or policy engine restart needed.

---

## Kong endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/customer/{id}` | Fetch customer record — fields masked per role |
| GET | `/api/unmask/{id}` | Fetch fully unmasked record — requires `X-Unmask-Reason` header |

### Required headers

| Header | When required |
|---|---|
| `Authorization: Bearer <token>` | All requests |
| `X-Unmask-Reason: <reason>` | Unmask endpoint only |
| `X-Access-Reference: <ref>` | Any request to a VIP customer |

---

## Manual API test

Enable direct grants temporarily for CLI testing by setting
`directAccessGrantsEnabled: true` in `keycloak/realm-config.json` for the
`website-client`, then rebuild.

```bash
# Obtain a token
TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=agent1&password=agent123&grant_type=password" \
  | jq -r .access_token)

# Standard request — response contains masked fields
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/customer/C002 | jq

# Unmask request — requires reason header
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Unmask-Reason: Billing dispute" \
  http://localhost:8000/api/unmask/C002 | jq

# VIP customer — requires both access reference and vip_agent/admin role
VIP_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=vip1&password=vip123&grant_type=password" \
  | jq -r .access_token)

curl -s \
  -H "Authorization: Bearer $VIP_TOKEN" \
  -H "X-Access-Reference: TICKET-2024-VIP-001" \
  http://localhost:8000/api/customer/C001 | jq

# Agent attempting VIP access — returns 403
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/customer/C001 | jq
```

---

## Response metadata

Every Kong response includes a `_masking` object showing what was applied:

```json
"_masking": {
  "applied": true,
  "role": "agent",
  "masked_fields": ["name", "msisdn", "email", "national_id", "address",
                    "last_call_duration", "data_roaming_gb", "last_location"],
  "gateway": "kong-opa",
  "is_vip": false
}
```

---

## Component map

```
.
├── docker-compose.yml          All services, healthchecks, startup ordering
│
├── keycloak/
│   └── realm-config.json       Auto-imported realm: users, roles, clients,
│                               logout redirect config
│
├── opa/
│   └── policy.rego             Access + masking policy
│                               References data.masking_config (populated
│                               at runtime by admin-service via OPA data API)
│
├── kong/
│   └── kong.yml                DB-less declarative config: routes + 3 plugins
│                               pre-function  — JWT decode + OPA call + VIP check
│                               post-function — response masking + audit log
│
├── admin-service/              Flask + SQLite — policy configuration console
│   ├── app.py                  CRUD for VIP list and masking rules;
│   │                           pushes to OPA /v1/data/masking_config on every change
│   └── templates/              Bootstrap 5 UI (login, dashboard, vip, roles)
│
├── crm-mock/
│   └── app.py                  Flask mock with 4 customers (C001–C004),
│                               L1 fields (name, msisdn, email, national_id, address),
│                               L2 fields (last_call_duration, data_roaming_gb,
│                               last_location), VIP flag on C001 and C004
│
├── website/
│   ├── app.py                  Flask portal: OIDC login, customer search,
│   │                           reveal (unmask) flow, VIP access reference prompt
│   └── templates/              Bootstrap 5 UI (index, search, customer detail)
│
└── log-dashboard/
    └── app.py                  Flask SSE log receiver and real-time viewer
                                Receives events from Kong, website, and CRM mock
```

---

## Startup order

Docker Compose enforces this sequence via `depends_on` and healthchecks:

```
OPA → Admin Service (seeds DB, syncs config to OPA) → Kong (OPA data ready)
Keycloak (demo realm imported)                       → Website
Log Dashboard → CRM Mock → Kong
```

Kong will not start until the Admin Service is healthy, ensuring OPA always
has masking rules loaded before the first request is processed.

---

## Production notes

**JWT validation**: In this demo Kong decodes the JWT payload locally
(base64url decode only — no signature verification). In production, place
Kong's built-in JWT plugin upstream of the pre-function plugin. The JWT
plugin verifies the signature against Keycloak's JWKS; the pre-function then
reads the already-validated claims. The Lua code requires no changes.

**OPA persistence**: OPA holds masking config in memory. On OPA restart,
the Admin Service must re-sync. Use the "Sync OPA" button or call
`POST /sync` on the admin service. For production, consider OPA bundle
mode for versioned, persistent policy distribution.

**Secrets**: Client secrets and admin passwords are hardcoded for demo
convenience. In production, inject via a secrets manager and rotate regularly.

**Admin service database**: SQLite is used for single-instance demo
simplicity. In production, replace with Postgres and enable proper
backup and retention for the sync_log audit trail.
