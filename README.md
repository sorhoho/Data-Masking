# Data Masking PoC — Keycloak · Kong · OPA · Admin GUI

A self-contained Docker Compose stack demonstrating **role-based PII masking enforced at the API
gateway**, with a live admin console for policy management and multi-backend field alias support.

---

## Table of contents

1. [Architecture](#architecture)
2. [How it works end-to-end](#how-it-works-end-to-end)
3. [Sequence diagrams](#sequence-diagrams)
   - [Standard CRM request](#1-standard-crm-request)
   - [VIP customer access](#2-vip-customer-access)
   - [Unmask request](#3-unmask-request)
   - [Billing subscriber lookup (alias masking)](#4-billing-subscriber-lookup)
   - [Add subscription](#5-add-subscription)
   - [Partner / M2M flow](#6-partner--m2m-flow)
4. [Data classification](#data-classification)
5. [Multi-backend field alias support](#multi-backend-field-alias-support)
6. [Role-based masking policy](#role-based-masking-policy)
7. [VIP customer controls](#vip-customer-controls)
8. [Partner role](#partner-role)
9. [Services](#services)
10. [Quick start](#quick-start)
11. [Demo users](#demo-users)
12. [Test data](#test-data)
13. [API reference](#api-reference)
14. [Sample requests and responses](#sample-requests-and-responses)
15. [OPA policy internals](#opa-policy-internals)
16. [Admin GUI](#admin-gui)
17. [Component map](#component-map)
18. [Startup order](#startup-order)
19. [Production notes](#production-notes)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Browser / API Client                                                   │
│    │  1. OIDC login (auth-code flow) or client_credentials (partner)   │
│    ▼                                                                    │
│  Keycloak :8080  ──  issues RS256-signed JWTs  ──  backed by Postgres  │
│                                                                         │
│  Website :3000  (OIDC code flow, Flask)                                 │
│    │  2. Bearer <JWT> on every backend request                          │
│    ▼                                                                    │
│  Kong Gateway :8000  (DB-less, Lua serverless plugins)                 │
│    │  3. Verify JWT RS256 signature — fetch JWKS from Keycloak,        │
│    │       cache per-worker (5-min TTL), match kid, verify signature   │
│    │  4. Resolve MSISDN → customer_id  (CRM internal, if needed)       │
│    │  5. Call OPA with role + customer_id + path + backend             │
│    │       ◄── allow/deny  +  masked_fields  +  is_vip                 │
│    │            +  backend_fields  (field alias registry)              │
│    │  6. Enforce X-Access-Reference for VIP + fire alert               │
│    │  7. Forward request                                                │
│    │       ├─► CRM Mock     :5000  (canonical field names)             │
│    │       └─► Billing Mock :5001  (aliased field names)               │
│    │           ◄── raw JSON                                             │
│    │  8. Two-pass response masking (Lua):                               │
│    │       Pass 1 — canonical field names (msisdn, name, …)            │
│    │       Pass 2 — backend aliases (mobilenum, subname, …)            │
│    │  9. Audit log ─────────────────────────────► Log Dashboard :9000  │
│    ▼                                                                         │
│  Masked JSON → rendered in browser                                      │
│                                                                         │
│  Admin GUI :8888  ──  config stored in PostgreSQL :5432                 │
│    VIP list · role-field matrix · backend field registry               │
│    served as OPA bundle (GET /bundle/masking_config.tar.gz)            │
│    OPA polls every 15–60 s — no manual push needed                     │
│                                                                         │
│  Log Dashboard :9000 ──► Loki :3100 ──► Grafana :3001 (dashboards)     │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key design decisions

| Decision | Reason |
|---|---|
| JWT RS256 verified in Kong via JWKS | Full cryptographic signature check — no per-request Keycloak round-trip; JWKS cached 5 min per Kong worker; key rotation handled by invalidating cache on unknown `kid` |
| OPA for masking decisions | Policy as code, live updates via Admin GUI without gateway restart |
| Admin service as OPA bundle server | VIP list and masking rules are operational config, not code — served as a versioned gzip tarball; OPA polls every 15–60 s, no manual push after restart |
| PostgreSQL for Admin Service and Keycloak | Durable, crash-safe storage; both services share a single Postgres instance with separate databases (`keycloak` and `admindb`) |
| Backend field alias registry | One role × field matrix applies to all backends; alias mapping is data, not code |
| Two-pass Lua masking | Pass 1 for canonical names, Pass 2 for backend-specific aliases with double-masking guard |
| Loki + Grafana for audit log persistence | Audit events forwarded from Log Dashboard to Loki (fire-and-forget); Grafana pre-provisions 6 panels — VIP alerts, OPA denials, unmask requests, billing, errors |
| CRM and Billing ports not exposed | All PII access must pass through Kong enforcement |

---

## How it works end-to-end

Every request through Kong goes through a fixed pipeline of three phases.

### Phase 1 — Pre-function (access control, `kong.yml` → `pre-function`)

1. **Extract Bearer token** from `Authorization` header — 401 if missing.
2. **Verify JWT RS256 signature** — fetch JWKS from `http://keycloak:8080/realms/demo/protocol/openid-connect/certs`, cache the key set per Kong worker for 5 minutes (keyed `"jwks_v1"` in `kong.cache`). Match the token's `kid` header against cached keys; if the `kid` is unknown, invalidate the cache and re-fetch once (handles key rotation). Convert the matching JWK to PEM via `resty.openssl.pkey`, then call `resty.jwt:verify_jwt_obj` with `valid_issuers` and a 10-second `lifetime_grace_period`. Reject with 401 on any signature or claims failure.
3. **Pick highest-priority role** from `realm_access.roles` (priority: admin > supervisor > vip_agent > agent/partner).
4. **Detect backend** from path prefix (`/api/billing/*` → `"billing"`, everything else → `"crm"`).
5. **Resolve MSISDN → customer_id** (for MSISDN-based routes) by calling CRM's internal `/api/resolve` endpoint. This gives OPA a stable customer_id for the VIP check.
6. **Call OPA** with `{role, username, path, method, customer_id, backend}`. Receive `{allow, masked_fields, is_vip, backend_fields}`.
7. **Enforce VIP rule**: if `is_vip=true` and `X-Access-Reference` header is missing → 400. If present, fire async alert to Log Dashboard.
8. **Enforce unmask rule**: `/api/unmask/*` requires `X-Unmask-Reason` header, then rewrites upstream path to `/api/customer/*`.
9. Store shared context (`masked_fields`, `backend_fields`, `user_role`, `is_vip`, …) in `kong.ctx.shared` for the masking phase.

### Phase 2 — Post-function (response masking, `kong.yml` → `post-function`)

Buffer the full response body, then:

1. **Pass 1** — iterate `MASKERS` (keyed by canonical field name) and mask any field listed in `masked_fields`.
2. **Pass 2** — iterate `backend_fields` (the alias registry returned by OPA). For each entry where `backend_field != canonical_field` and the canonical is in `masked_fields`, apply the same masking function. The `!=` guard prevents double-masking on CRM responses where field names are already canonical.
3. Append `_masking` metadata object to the JSON response.
4. Fire async audit log event.

### Phase 3 — Log (audit trail, `kong.yml` → `post-function.log`)

Fire-and-forget POST to Log Dashboard containing: service, level, event type, path, backend, customer_id, role, OPA decision, masked field count, VIP flag, access reference, and MSISDN hint.

---

## Sequence diagrams

### 1. Standard CRM request

```mermaid
sequenceDiagram
    participant B as Browser
    participant W as Website :3000
    participant KC as Keycloak :8080
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000
    participant LD as Log Dashboard :9000

    B->>W: GET /customer/C002
    W->>K: GET /api/customer/C002\nAuthorization: Bearer <JWT>
    K->>K: Fetch JWKS (5-min cache, match kid)\nVerify RS256 signature + claims\nExtract role from realm_access.roles
    K->>OPA: POST /v1/data/data_masking\n{role:"agent", customer_id:"C002",\n path:"/api/customer/C002", backend:"crm"}
    OPA-->>K: {allow:true, is_vip:false,\n masked_fields:["name","msisdn","email",\n "national_id","address","last_call_duration",\n "data_roaming_gb","last_location"],\n backend_fields:{}}
    K->>CRM: GET /api/customer/C002
    CRM-->>K: {id:"C002", name:"Siti Nurhaliza",\n msisdn:"+60198765432", ...}
    K->>K: Pass 1: mask canonical fields\nname→"S*** N*******"\nmsisdn→"+6019****32"\nemail→"s*****i@email.com" ...
    K->>LD: POST /log (audit, async)
    K-->>W: {id:"C002", name:"S*** N*******",\n msisdn:"+6019****32", ...,\n _masking:{role:"agent", masked_fields:[...]}}
    W-->>B: Render masked customer page
```

### 2. VIP customer access

```mermaid
sequenceDiagram
    participant W as Website :3000
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000
    participant LD as Log Dashboard :9000

    Note over W,K: vip_agent role, customer C001 (VIP)

    W->>K: GET /api/customer/C001\nAuthorization: Bearer <VIP_JWT>
    K->>OPA: POST /v1/data/data_masking\n{role:"vip_agent", customer_id:"C001", ...}
    OPA-->>K: {allow:true, is_vip:true, masked_fields:[]}
    K->>K: is_vip=true → check X-Access-Reference header
    alt Header missing
        K-->>W: 400 {"message":"X-Access-Reference header\n is required for VIP customer access"}
        W->>W: Render access-reference form
        W->>K: GET /api/customer/C001\nX-Access-Reference: TICKET-2024-VIP-001
    end
    K->>LD: POST /log {event:"vip_access_alert",\n customer_id:"C001", access_reference:"TICKET-2024-VIP-001"}\n(async, real-time alert)
    K->>CRM: GET /api/customer/C001
    CRM-->>K: {id:"C001", name:"Ahmad bin Abdullah", ...}
    K->>K: masked_fields=[] → no masking applied
    K->>LD: POST /log (audit)
    K-->>W: {id:"C001", name:"Ahmad bin Abdullah", ...,\n _masking:{is_vip:true, masked_fields:[]}}

    Note over W,K: agent role attempting VIP access
    W->>K: GET /api/customer/C001\nAuthorization: Bearer <AGENT_JWT>
    K->>OPA: {role:"agent", customer_id:"C001", ...}
    OPA-->>K: {allow:false, is_vip:true}
    K-->>W: 403 {"message":"Access denied: VIP customer\n requires vip_agent or admin role"}
```

### 3. Unmask request

```mermaid
sequenceDiagram
    participant W as Website :3000
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000
    participant LD as Log Dashboard :9000

    Note over W,K: supervisor role — /api/unmask rewrites to /api/customer upstream

    W->>K: GET /api/unmask/C002\nAuthorization: Bearer <SUPER_JWT>\nX-Unmask-Reason: Billing dispute ref #4521
    K->>K: Verify JWT RS256 → role="supervisor"
    K->>OPA: POST /v1/data/data_masking\n{role:"supervisor", customer_id:"C002",\n path:"/api/unmask/C002", backend:"crm"}
    OPA-->>K: {allow:true, is_vip:false, masked_fields:[]}
    Note over K: OPA returns masked_fields=[] for /api/unmask path
    K->>K: X-Unmask-Reason present ✓\nRewrite upstream path:\n/api/unmask/C002 → /api/customer/C002
    K->>CRM: GET /api/customer/C002
    CRM-->>K: {id:"C002", name:"Siti Nurhaliza", ...}
    K->>K: masked_fields=[] → no masking
    K->>LD: POST /log {event:"unmask_request",\n unmask_reason:"Billing dispute ref #4521", ...}
    K-->>W: Full unmasked JSON + _masking:{masked_fields:[]}
```

### 4. Billing subscriber lookup

```mermaid
sequenceDiagram
    participant W as Website :3000
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000
    participant BL as Billing Mock :5001
    participant LD as Log Dashboard :9000

    Note over W,K: agent role — billing backend uses aliased field names

    W->>K: GET /api/billing/subscriber?msisdn=+60198765432\nAuthorization: Bearer <AGENT_JWT>
    K->>K: Detect backend: path starts /api/billing → backend="billing"
    K->>CRM: GET /api/resolve?msisdn=+60198765432\n(internal, best-effort for VIP check)
    CRM-->>K: {customer_id:"C002"}
    K->>OPA: POST /v1/data/data_masking\n{role:"agent", customer_id:"C002",\n backend:"billing", path:"/api/billing/subscriber"}
    OPA-->>K: {allow:true, is_vip:false,\n masked_fields:["name","msisdn",...],\n backend_fields:{\n  "mobilenum":{canonical:"msisdn",classification:"L1"},\n  "subname":{canonical:"name",classification:"L1"},\n  "ic_num":{canonical:"national_id",classification:"L1"},\n  "billing_address":{canonical:"address",classification:"L1"},\n  "call_duration_s":{canonical:"last_call_duration",classification:"L2"},\n  "roaming_gb":{canonical:"data_roaming_gb",classification:"L2"}\n}}
    K->>BL: GET /api/billing/subscriber?msisdn=+60198765432
    BL-->>K: {mobilenum:"+60198765432", subname:"Siti Nurhaliza", ic_num:"920720-10-8812",\n billing_address:"Block 7, Jalan Mawar...", call_duration_s:87, roaming_gb:0.0, ...}
    K->>K: Pass 1: canonical fields — none present in billing response (no "msisdn" key)\nPass 2: aliases — mobilenum→mask_msisdn, subname→mask_name,\n         ic_num→mask_national_id, billing_address→mask_address,\n         call_duration_s→mask_redact, roaming_gb→mask_redact
    K->>LD: POST /log (audit, backend="billing")
    K-->>W: {mobilenum:"+6019****32", subname:"S*** N*******",\n ic_num:"92**************", billing_address:"*** (redacted)",\n call_duration_s:"***", roaming_gb:"***",\n _masking:{backend:"billing", masked_fields:[...]}}
```

### 5. Add subscription

```mermaid
sequenceDiagram
    participant W as Website :3000
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000
    participant LD as Log Dashboard :9000

    W->>K: POST /api/subscription\nAuthorization: Bearer <JWT>\n{msisdn:"+60198765432", plan:"Postpaid 100GB"}
    K->>K: Read body, extract msisdn
    K->>CRM: GET /api/resolve?msisdn=+60198765432
    CRM-->>K: {customer_id:"C002"}
    K->>OPA: POST /v1/data/data_masking\n{role:"agent", customer_id:"C002",\n path:"/api/subscription", method:"POST"}
    OPA-->>K: {allow:true, is_vip:false, masked_fields:[...]}
    K->>CRM: POST /api/subscription\n{msisdn:"+60198765432", plan:"Postpaid 100GB"}
    CRM-->>K: {subscription_id:"sub-<uuid>", customer_id:"C002",\n msisdn:"+60198765432", plan:"Postpaid 100GB",\n status:"active", activated_at:"2024-03-01T12:00:00"}
    K->>K: Apply masking to response (msisdn masked for agent)
    K->>LD: POST /log {event:"subscription_request", ...}
    K-->>W: {subscription_id:"sub-...", customer_id:"C002",\n msisdn:"+6019****32", plan:"Postpaid 100GB",\n status:"active", _masking:{...}}
```

### 6. Partner / M2M flow

```mermaid
sequenceDiagram
    participant P as Partner System
    participant KC as Keycloak :8080
    participant K as Kong :8000
    participant OPA as OPA :8181
    participant CRM as CRM Mock :5000

    P->>KC: POST /realms/demo/protocol/openid-connect/token\ngrant_type=client_credentials\nclient_id=partner-client&client_secret=<secret>
    KC-->>P: {access_token:"<JWT with role=partner>", ...}

    P->>K: GET /api/customer/C002\nAuthorization: Bearer <PARTNER_JWT>
    K->>K: Verify JWT RS256 → realm_access.roles=["partner"]
    K->>OPA: {role:"partner", customer_id:"C002", path:"/api/customer/C002"}
    OPA-->>K: {allow:true, is_vip:false,\n masked_fields:["name","msisdn","email","national_id",\n "address","last_call_duration","data_roaming_gb","last_location"]}
    Note over OPA: Partner always gets full L1+L2 masking\nCannot access VIP customers\nCannot call /api/unmask
    K->>CRM: GET /api/customer/C002
    CRM-->>K: raw JSON
    K->>K: Mask all 8 L1+L2 fields
    K-->>P: Fully masked JSON

    Note over P,K: Partner attempting VIP access
    P->>K: GET /api/customer/C001
    K->>OPA: {role:"partner", customer_id:"C001", ...}
    OPA-->>K: {allow:false}  ← VIP customer, partner denied
    K-->>P: 403 {"message":"Access denied by security policy"}
```

---

## Data classification

Fields are classified into two sensitivity levels. OPA returns the list of fields to mask per role;
Kong applies the appropriate masking function.

### L1 — Direct identifiers

| Field (canonical) | Masking function | Example input | Example output |
|---|---|---|---|
| `name` | First letter of each word kept, rest starred | `Ahmad bin Abdullah` | `A**** b** A*******` |
| `msisdn` | Country prefix kept, last 2 digits kept | `+60198765432` | `+6019****32` |
| `email` | First + last char of local part kept | `siti@email.com` | `s***i@email.com` |
| `national_id` | First 2 chars kept | `920720-10-8812` | `92************` |
| `address` | Fully redacted | `Block 7, Jalan Mawar` | `*** (redacted)` |

### L2 — Linkable / profiling data

| Field (canonical) | Masking function | Example output |
|---|---|---|
| `last_call_duration` | Full redact | `***` |
| `data_roaming_gb` | Full redact | `***` |
| `last_location` | Full redact | `***` |

---

## Multi-backend field alias support

Different backend systems may name the same PII concept differently. The alias registry in the
Admin GUI maps backend-specific field names to canonical names, allowing the same role × field
masking matrix to apply across all backends.

### How it works

```
Admin GUI
  └─ field_mappings table (PostgreSQL)
       billing/mobilenum → canonical:msisdn, L1
       billing/subname   → canonical:name,   L1
       ...
       │
       ▼ served as bundle: GET /bundle/masking_config.tar.gz
OPA policy.rego
  └─ backend_fields rule
       input.backend = "billing"
       → returns {mobilenum:{canonical:"msisdn",...}, subname:{canonical:"name",...}, ...}
       │
       ▼ returned in OPA response
Kong post-function
  └─ Pass 1: mask data["msisdn"] if present
     Pass 2: for each alias where canon != bfield
               if data["mobilenum"] present and "msisdn" in masked_fields
                 apply mask_msisdn to data["mobilenum"]
```

### Registered backends (defaults)

| Backend ID | Display name | Base URL | Notes |
|---|---|---|---|
| `crm` | CRM System | `http://crm-mock:5000` | Canonical field names — Pass 2 has no effect |
| `billing` | Billing System | `http://billing-mock:5001` | Aliased field names — Pass 2 handles these |

### Billing field alias map

| Billing field | Canonical field | Classification |
|---|---|---|
| `mobilenum` | `msisdn` | L1 |
| `subname` | `name` | L1 |
| `ic_num` | `national_id` | L1 |
| `billing_address` | `address` | L1 |
| `call_duration_s` | `last_call_duration` | L2 |
| `roaming_gb` | `data_roaming_gb` | L2 |

Adding a new backend only requires registering its field mappings in the Admin GUI. No OPA policy
changes, no Kong plugin changes.

---

## Role-based masking policy

Masking rules are live-configurable via the Admin GUI. The defaults:

| Field | Class | agent | supervisor | vip\_agent | admin | partner |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `name` | L1 | masked | clear | clear | clear | masked |
| `msisdn` | L1 | masked | masked | clear | clear | masked |
| `email` | L1 | masked | clear | clear | clear | masked |
| `national_id` | L1 | masked | masked | clear | clear | masked |
| `address` | L1 | masked | clear | clear | clear | masked |
| `last_call_duration` | L2 | masked | clear | clear | clear | masked |
| `data_roaming_gb` | L2 | masked | clear | clear | clear | masked |
| `last_location` | L2 | masked | clear | clear | clear | masked |

---

## VIP customer controls

Customers `C001` (Ahmad) and `C004` (Mei Ling) are flagged as VIP. Stronger controls apply:

| Role | VIP access |
|---|---|
| `agent` | 403 — blocked entirely |
| `supervisor` | 403 — blocked entirely |
| `vip_agent` | Allowed — must supply `X-Access-Reference` header on every request |
| `admin` | Allowed — must supply `X-Access-Reference` header on every request |
| `partner` | 403 — blocked entirely (M2M partners cannot access VIP data) |

- **Real-time alert**: Kong fires a `vip_access_alert` event to the Log Dashboard immediately, before forwarding the request upstream.
- **Audit trail**: Every VIP access is logged with username, role, reference, customer ID, and timestamp.
- **Live config**: The VIP list is managed in the Admin GUI and takes effect on the next request — no restart needed.

---

## Partner role

The `partner` client uses **client credentials flow** (M2M — no human login). It receives full
L1 + L2 masking on every field and has no path to unmask data.

```bash
# Obtain a partner token (client credentials)
PARTNER_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=partner-client&client_secret=partner-secret-456" \
  -d "grant_type=client_credentials" \
  | jq -r .access_token)

# Partner request — all PII masked
curl -s -H "Authorization: Bearer $PARTNER_TOKEN" \
  http://localhost:8000/api/customer/C002 | jq
```

Rules enforced at the OPA layer (cannot be bypassed even with valid tokens):
- VIP customers → 403
- `/api/unmask/*` → 403 (partner is excluded from the `allow` rule for unmask)
- Full L1+L2 masking always applied

---

## Services

| Service | URL | Purpose |
|---|---|---|
| Website | http://localhost:3000 | Agent-facing CRM portal (OIDC login, search, VIP flow) |
| Keycloak | http://localhost:8080 | Identity provider — OIDC, RS256 JWT issuer (backed by PostgreSQL) |
| Kong Gateway | http://localhost:8000 | API gateway — JWT RS256 verify, OPA, masking, audit |
| Kong Admin | http://localhost:8001 | Kong admin API (read-only metrics / config inspection) |
| OPA | http://localhost:8181 | Policy engine — bundle mode, polls admin-service every 15–60 s |
| Admin GUI | http://localhost:8888 | Live policy configuration (VIP, roles, backends) |
| Log Dashboard | http://localhost:9000 | Real-time audit log viewer (forwards events to Loki) |
| Loki | http://localhost:3100 | Log aggregation — persists audit events from Log Dashboard |
| Grafana | http://localhost:3001 | Pre-built dashboards — VIP alerts, OPA denials, unmask, billing |
| PostgreSQL | localhost:5432 | Persistent storage for Keycloak (`keycloak` DB) and Admin Service (`admindb`) |
| CRM Mock | internal only | Raw customer data — canonical PII field names |
| Billing Mock | internal only | Raw subscriber data — aliased PII field names |

---

## Quick start

```bash
git clone <repo>
cd Data-Masking
docker compose up --build
```

First boot takes **3–4 minutes** — PostgreSQL initialises both databases (`keycloak` and `admindb`),
Keycloak imports the `demo` realm, and the Admin Service seeds its tables before Kong starts.
OPA receives its first bundle from the Admin Service within a few seconds of OPA coming up.
Docker Compose enforces the startup order via healthchecks — nothing starts until its dependency
is healthy.

Once all containers are up, open **http://localhost:3000**.

---

## Demo users

| Username | Password | Role | Notes |
|---|---|---|---|
| `agent1` | `agent123` | agent | Full L1+L2 masking; VIP blocked |
| `supervisor1` | `super123` | supervisor | L1 partial (msisdn + national_id masked); VIP blocked |
| `vip1` | `vip123` | vip\_agent | No masking; VIP allowed with access reference |
| `admin1` | `admin123` | admin | No masking; VIP allowed with access reference |

**Admin GUI**: http://localhost:8888 — `admin / admin123`

---

## Test data

### CRM customers (canonical field names)

| ID | Name | MSISDN | VIP | Notes |
|---|---|---|---|---|
| C001 | Ahmad bin Abdullah | +60123456789 | Yes | Requires access reference |
| C002 | Siti Nurhaliza binti Tarudin | +60198765432 | No | Standard access |
| C003 | Rajesh Kumar Sharma | +60112233445 | No | Suspended account |
| C004 | Mei Ling Tan | +60167890123 | Yes | Requires access reference |

### Billing subscribers (aliased field names)

Same 4 people, exposed by the billing backend with different field names:

| MSISDN | `subname` | `mobilenum` | Plan | Outstanding |
|---|---|---|---|---|
| +60123456789 | Ahmad bin Abdullah | +60123456789 | PP100 (Postpaid 100GB) | 0.00 |
| +60198765432 | Siti Nurhaliza binti Tarudin | +60198765432 | PRE20 (Prepaid 20GB) | 5.50 |
| +60112233445 | Rajesh Kumar Sharma | +60112233445 | PP50 (Postpaid 50GB) | 118.00 |
| +60167890123 | Mei Ling Tan | +60167890123 | PP200 (Postpaid 200GB) | 0.00 |

---

## API reference

All endpoints require `Authorization: Bearer <token>`.

| Method | Path | Backend | Description |
|---|---|---|---|
| GET | `/api/customer/{id}` | CRM | Fetch customer by ID — fields masked per role |
| GET | `/api/customer?msisdn={msisdn}` | CRM | Fetch customer by MSISDN (Kong resolves → customer_id) |
| GET | `/api/unmask/{id}` | CRM | Fetch fully unmasked record (requires `X-Unmask-Reason`) |
| GET | `/api/billing/subscriber?msisdn={msisdn}` | Billing | Fetch billing subscriber — aliases masked per role |
| POST | `/api/subscription` | CRM | Add a subscription (body: `{msisdn, plan}`) |

### Request headers

| Header | When required |
|---|---|
| `Authorization: Bearer <token>` | All requests |
| `X-Unmask-Reason: <reason>` | `/api/unmask/*` only |
| `X-Access-Reference: <ticket>` | Any request for a VIP customer |

---

## Sample requests and responses

Enable direct grants for CLI testing by adding `"directAccessGrantsEnabled": true` in
`keycloak/realm-config.json` for `website-client`, then `docker compose up --build`.

```bash
# ── Obtain tokens ──────────────────────────────────────────────────────────────
AGENT_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=agent1&password=agent123&grant_type=password" \
  | jq -r .access_token)

VIP_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=vip1&password=vip123&grant_type=password" \
  | jq -r .access_token)

PARTNER_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=partner-client&client_secret=partner-secret-456" \
  -d "grant_type=client_credentials" \
  | jq -r .access_token)
```

---

### GET /api/customer/C002 — agent role

```bash
curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
  http://localhost:8000/api/customer/C002 | jq
```

**Response (200)**
```json
{
  "id": "C002",
  "name": "S*** N********* b**** T******",
  "msisdn": "+6019****32",
  "email": "s***i@email.com",
  "national_id": "92************",
  "address": "*** (redacted)",
  "plan": "Prepaid 20GB",
  "status": "active",
  "last_call_duration": "***",
  "data_roaming_gb": "***",
  "last_location": "***",
  "_masking": {
    "applied": true,
    "role": "agent",
    "masked_fields": ["name", "msisdn", "email", "national_id", "address",
                      "last_call_duration", "data_roaming_gb", "last_location"],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "crm"
  }
}
```

---

### GET /api/customer/C002 — supervisor role

```bash
SUPER_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/demo/protocol/openid-connect/token \
  -d "client_id=website-client&client_secret=website-secret-123" \
  -d "username=supervisor1&password=super123&grant_type=password" \
  | jq -r .access_token)

curl -s -H "Authorization: Bearer $SUPER_TOKEN" \
  http://localhost:8000/api/customer/C002 | jq
```

**Response (200)** — supervisor sees name, email, address; msisdn and national_id still masked
```json
{
  "id": "C002",
  "name": "Siti Nurhaliza binti Tarudin",
  "msisdn": "+6019****32",
  "email": "siti@email.com",
  "national_id": "92************",
  "address": "Block 7, Jalan Mawar, 40150 Shah Alam",
  "plan": "Prepaid 20GB",
  "status": "active",
  "last_call_duration": 87,
  "data_roaming_gb": 0.0,
  "last_location": "Shah Alam",
  "_masking": {
    "applied": true,
    "role": "supervisor",
    "masked_fields": ["msisdn", "national_id"],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "crm"
  }
}
```

---

### GET /api/customer/C001 — agent blocked on VIP

```bash
curl -s -H "Authorization: Bearer $AGENT_TOKEN" \
  http://localhost:8000/api/customer/C001 | jq
```

**Response (403)**
```json
{
  "error": true,
  "message": "Access denied: VIP customer requires vip_agent or admin role"
}
```

---

### GET /api/customer/C001 — vip_agent with access reference

```bash
# Missing header — Kong blocks before calling upstream
curl -s -H "Authorization: Bearer $VIP_TOKEN" \
  http://localhost:8000/api/customer/C001 | jq
```

**Response (400)**
```json
{
  "error": true,
  "message": "X-Access-Reference header is required for VIP customer access"
}
```

```bash
# With access reference — full unmasked data (vip_agent has empty masked_fields)
curl -s \
  -H "Authorization: Bearer $VIP_TOKEN" \
  -H "X-Access-Reference: TICKET-2024-VIP-001" \
  http://localhost:8000/api/customer/C001 | jq
```

**Response (200)**
```json
{
  "id": "C001",
  "name": "Ahmad bin Abdullah",
  "msisdn": "+60123456789",
  "email": "ahmad@example.com",
  "national_id": "850315-14-5678",
  "address": "No. 12, Jalan Ampang, 50450 Kuala Lumpur",
  "plan": "Postpaid 100GB",
  "status": "active",
  "last_call_duration": 342,
  "data_roaming_gb": 1.2,
  "last_location": "Kuala Lumpur",
  "_masking": {
    "applied": true,
    "role": "vip_agent",
    "masked_fields": [],
    "gateway": "kong-opa",
    "is_vip": true,
    "backend": "crm"
  }
}
```

---

### GET /api/unmask/C002 — supervisor role

```bash
curl -s \
  -H "Authorization: Bearer $SUPER_TOKEN" \
  -H "X-Unmask-Reason: Billing dispute ref #4521" \
  http://localhost:8000/api/unmask/C002 | jq
```

**Response (200)** — OPA returns `masked_fields=[]` for `/api/unmask` path
```json
{
  "id": "C002",
  "name": "Siti Nurhaliza binti Tarudin",
  "msisdn": "+60198765432",
  "email": "siti@email.com",
  "national_id": "920720-10-8812",
  "address": "Block 7, Jalan Mawar, 40150 Shah Alam",
  "plan": "Prepaid 20GB",
  "status": "active",
  "last_call_duration": 87,
  "data_roaming_gb": 0.0,
  "last_location": "Shah Alam",
  "_masking": {
    "applied": true,
    "role": "supervisor",
    "masked_fields": [],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "crm"
  }
}
```

**Without X-Unmask-Reason (400)**
```json
{
  "error": true,
  "message": "X-Unmask-Reason header is required for data unmasking"
}
```

---

### GET /api/billing/subscriber — agent role (alias masking)

```bash
curl -s \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  "http://localhost:8000/api/billing/subscriber?msisdn=+60198765432" | jq
```

**Response (200)** — billing aliases masked via Pass 2; non-PII fields (account_type, outstanding_bill, …) are untouched
```json
{
  "mobilenum": "+6019****32",
  "subname": "S*** N**** b*** T******",
  "ic_num": "92**************",
  "billing_address": "*** (redacted)",
  "account_type": "prepaid",
  "plan_code": "PRE20",
  "outstanding_bill": 5.5,
  "last_bill_date": "2024-02-28",
  "data_usage_gb": 18.1,
  "call_duration_s": "***",
  "roaming_gb": "***",
  "_masking": {
    "applied": true,
    "role": "agent",
    "masked_fields": ["name", "msisdn", "email", "national_id", "address",
                      "last_call_duration", "data_roaming_gb", "last_location"],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "billing"
  }
}
```

---

### POST /api/subscription — add subscription

```bash
curl -s -X POST \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"msisdn": "+60198765432", "plan": "Postpaid 100GB"}' \
  http://localhost:8000/api/subscription | jq
```

**Response (200)**
```json
{
  "subscription_id": "sub-3a7f2b1c-9e4d-48a0-b123-dc9a0e7f1234",
  "customer_id": "C002",
  "msisdn": "+6019****32",
  "plan": "Postpaid 100GB",
  "status": "active",
  "activated_at": "2024-03-01T12:34:56",
  "_masking": {
    "applied": true,
    "role": "agent",
    "masked_fields": ["name", "msisdn", "email", "national_id", "address",
                      "last_call_duration", "data_roaming_gb", "last_location"],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "crm"
  }
}
```

---

### Partner — full L1+L2 masking (M2M)

```bash
curl -s -H "Authorization: Bearer $PARTNER_TOKEN" \
  http://localhost:8000/api/customer/C002 | jq
```

**Response (200)** — all 8 L1+L2 fields masked, same as agent
```json
{
  "id": "C002",
  "name": "S*** N********* b**** T******",
  "msisdn": "+6019****32",
  "email": "s***i@email.com",
  "national_id": "92************",
  "address": "*** (redacted)",
  "plan": "Prepaid 20GB",
  "status": "active",
  "last_call_duration": "***",
  "data_roaming_gb": "***",
  "last_location": "***",
  "_masking": {
    "applied": true,
    "role": "partner",
    "masked_fields": ["name", "msisdn", "email", "national_id", "address",
                      "last_call_duration", "data_roaming_gb", "last_location"],
    "gateway": "kong-opa",
    "is_vip": false,
    "backend": "crm"
  }
}
```

---

## OPA policy internals

**Policy file**: `opa/policy.rego`  
**Runtime config**: `opa/opa-config.yaml`

OPA runs in **v0-compatible mode** (`--v0-compatible`) with **bundle mode** enabled.
The masking config is not baked into the policy — the Admin Service serves it as a gzip tarball
at `GET /bundle/masking_config.tar.gz`. OPA polls every 15–60 seconds, so changes made via the
Admin GUI automatically take effect without a manual sync. **Decision logging** is enabled
(`decision_logs.console: true`) — every policy evaluation is emitted as structured JSON to
stdout, captured by Docker and queryable via Loki/Grafana.

### Data shape served by admin-service bundle

```json
{
  "vip_customers": {
    "C001": true,
    "C004": true
  },
  "role_masked_fields": {
    "agent":      ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],
    "supervisor": ["msisdn", "national_id"],
    "vip_agent":  [],
    "admin":      [],
    "partner":    ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"]
  },
  "backends": {
    "crm": {
      "msisdn":             {"canonical": "msisdn",             "classification": "L1"},
      "name":               {"canonical": "name",               "classification": "L1"}
    },
    "billing": {
      "mobilenum":          {"canonical": "msisdn",             "classification": "L1"},
      "subname":            {"canonical": "name",               "classification": "L1"},
      "ic_num":             {"canonical": "national_id",        "classification": "L1"},
      "billing_address":    {"canonical": "address",            "classification": "L1"},
      "call_duration_s":    {"canonical": "last_call_duration", "classification": "L2"},
      "roaming_gb":         {"canonical": "data_roaming_gb",    "classification": "L2"}
    }
  }
}
```

### Key rules

```rego
# Allow regular roles only for non-VIP customers
allow {
    input.role == "agent"
    not vip_customers[input.customer_id]
}

# Partner: allowed for non-VIP, non-unmask paths
allow {
    input.role == "partner"
    not vip_customers[input.customer_id]
    not startswith(input.path, "/api/unmask")
}

# masked_fields = [] on the unmask path (caller explicitly requested full data)
masked_fields = [] {
    startswith(input.path, "/api/unmask")
}

# backend_fields returns the alias registry for the requesting backend
backend_fields = f {
    f := data.masking_config.backends[input.backend]
}
```

### OPA input / output contract

**Input (Kong → OPA)**
```json
{
  "input": {
    "role":        "agent",
    "username":    "agent1",
    "path":        "/api/customer/C002",
    "method":      "GET",
    "customer_id": "C002",
    "backend":     "crm"
  }
}
```

**Output (OPA → Kong)** — `result` key
```json
{
  "result": {
    "allow":          true,
    "is_vip":         false,
    "masked_fields":  ["name", "msisdn", "email", "national_id", "address",
                       "last_call_duration", "data_roaming_gb", "last_location"],
    "backend_fields": {
      "msisdn": {"canonical": "msisdn", "classification": "L1"},
      "name":   {"canonical": "name",   "classification": "L1"}
    }
  }
}
```

---

## Admin GUI

Open **http://localhost:8888** and log in with `admin / admin123`.

| Page | Path | What you can do |
|---|---|---|
| Dashboard | `/` | Summary cards: VIP count, active mask rules, role count, backend count, last sync time |
| VIP Customers | `/vip` | Add or remove VIP customer IDs — OPA picks up the change within 60 s |
| Masking Rules | `/roles` | Checkbox matrix of role × field — save persists to PostgreSQL; OPA re-polls automatically |
| Backends | `/backends` | Register backends, add/remove field alias mappings |
| Sync OPA | POST `/sync` | Records a sync_log entry and returns a reminder that OPA will re-poll within 60 s (bundle mode — no direct push) |
| Live config | GET `/api/config` | JSON view of the exact masking_config payload the bundle currently serves |

**Changes persist to PostgreSQL immediately and are reflected in OPA within 15–60 seconds — no gateway or policy engine restart needed.**

---

## Component map

```
.
├── docker-compose.yml          Service wiring, healthchecks, startup ordering
│                               Services: postgres, keycloak, opa, admin-service,
│                               kong, crm-mock, billing-mock, website,
│                               log-dashboard, loki, grafana
│
├── postgres/
│   └── init.sql                Runs once on first volume creation: creates the
│                               admindb database + adminuser (Keycloak uses the
│                               default keycloak DB created by the image)
│
├── keycloak/
│   └── realm-config.json       Auto-imported realm: users (agent1, supervisor1,
│                               vip1, admin1), roles, clients (website-client,
│                               partner-client), service account for partner
│
├── opa/
│   ├── policy.rego             Access + masking policy (v0 syntax)
│   │                           References data.masking_config loaded via bundle
│   └── opa-config.yaml         Bundle mode config: polls admin-service every
│                               15–60 s; decision_logs.console=true (structured
│                               JSON to stdout for Loki capture)
│
├── kong/
│   └── kong.yml                DB-less declarative config
│                               ├─ services: crm-service, billing-service
│                               ├─ routes: customer, unmask, subscription, billing
│                               └─ plugins (global):
│                                   cors         — CORS headers
│                                   pre-function — JWT RS256 verify (JWKS fetch +
│                                                  per-worker 5-min cache + kid
│                                                  rotation), MSISDN resolve,
│                                                  OPA call, VIP/unmask enforce
│                                   post-function — two-pass masking + audit log
│
├── admin-service/
│   ├── app.py                  Flask + PostgreSQL CRUD (psycopg2-binary)
│   │                           Tables: fields, vip_customers, role_masked_fields,
│   │                                   backends, field_mappings, sync_log
│   │                           GET /bundle/masking_config.tar.gz — gzip tarball
│   │                           consumed by OPA bundle polling
│   ├── requirements.txt        flask, requests, psycopg2-binary
│   └── templates/
│       ├── base.html           Bootstrap 5 nav shell
│       ├── dashboard.html      5-card summary + masking matrix + sync log
│       ├── vip.html            VIP customer management
│       ├── roles.html          Role × field checkbox matrix
│       └── backends.html       Backend registry + field alias accordion
│
├── crm-mock/
│   └── app.py                  Flask mock, 4 customers (C001–C004)
│                               Canonical field names: name, msisdn, email,
│                               national_id, address, last_call_duration,
│                               data_roaming_gb, last_location
│                               Endpoints: /health, /api/customer/{id},
│                               /api/customer?msisdn=, /api/resolve?msisdn=,
│                               POST /api/subscription
│
├── billing-mock/
│   └── app.py                  Flask mock, same 4 customers via MSISDN
│                               Aliased field names: mobilenum, subname, ic_num,
│                               billing_address, call_duration_s, roaming_gb
│                               Non-PII: account_type, plan_code, outstanding_bill,
│                               last_bill_date, data_usage_gb
│                               Endpoints: /health, /api/billing/subscriber?msisdn=
│
├── website/
│   ├── app.py                  Flask portal: OIDC auth code flow, customer by ID,
│   │                           customer by MSISDN, billing subscriber by MSISDN,
│   │                           reveal (unmask), add subscription
│   └── templates/
│       ├── base.html           Bootstrap 5 shell + Bootstrap JS bundle
│       ├── index.html          Landing / login page
│       ├── search.html         Three-card search: customer ID, CRM MSISDN,
│       │                       Billing MSISDN; quick-access test customer cards
│       ├── customer.html       CRM customer detail: masked fields, VIP gate,
│       │                       unmask panel, add-subscription panel
│       └── subscriber.html     Billing subscriber detail: aliased fields with
│                               canonical mapping + L1/L2 badges
│
├── log-dashboard/
│   ├── app.py                  Flask SSE receiver — receives audit events from
│   │                           Kong and forwards each to Loki (fire-and-forget
│   │                           daemon thread, 1 s timeout); in-memory ring
│   │                           buffer (last 500 events) for /logs SSE stream
│   └── requirements.txt        flask, requests
│
└── grafana/
    └── provisioning/
        ├── datasources/
        │   └── loki.yaml       Auto-provisions Loki datasource at http://loki:3100
        └── dashboards/
            ├── dashboard.yaml  File provider config
            └── data-masking.json  6-panel dashboard:
                                   All Events · VIP Access Alerts · OPA Denials
                                   Unmask Requests · Errors & Warnings
                                   Billing Backend Requests
```

---

## Startup order

Docker Compose enforces this sequence:

```
postgres (healthy — creates keycloak DB + admindb via init.sql)
  ├─► keycloak (started — imports demo realm; retries until postgres is healthy)
  │     └─► website (started — retries OIDC redirect until Keycloak realm is ready)
  └─► admin-service (healthy — connects to admindb, seeds tables)
        └─► opa (started — immediately polls /bundle/masking_config.tar.gz)

loki (healthy)
  └─► log-dashboard (healthy — ready to receive audit events and forward to Loki)
        ├─► crm-mock    (healthy)
        ├─► billing-mock (healthy)
        └─► kong (started — all dependencies healthy, first request is safe)

grafana (started — auto-provisions Loki datasource + data-masking dashboard)
```

Key guarantees:
- Kong never starts until Admin Service is healthy, so OPA has received its first bundle before any request arrives.
- OPA never starts until Admin Service is healthy, so the first bundle poll always succeeds.
- Log Dashboard is healthy before Kong starts, so no audit events are lost.
- Loki is healthy before Log Dashboard starts, so forwarded events land immediately.
- Keycloak and Website use `restart: on-failure` to handle realm import timing.

---

## Production notes

### Implemented hardening

**JWT RS256 signature verification** ✅  
Kong fetches JWKS from Keycloak, caches per worker (5-min TTL), and verifies every token's
RS256 signature before reading claims. Key rotation is handled automatically — on unknown `kid`,
the cache is invalidated and keys are re-fetched once.

**PostgreSQL persistence** ✅  
Both Keycloak and the Admin Service use a shared PostgreSQL 16 instance with separate databases.
Data survives container restarts via the `postgres-data` Docker volume.

**OPA bundle mode** ✅  
OPA polls the Admin Service for a gzip bundle every 15–60 seconds. Config is never lost on
restart — no manual re-sync required. Decision logging (`decision_logs.console: true`) emits
every evaluation as structured JSON to stdout, queryable via Loki.

**Persistent audit log** ✅  
Log Dashboard forwards every audit event to Loki (fire-and-forget). Grafana at `:3001`
auto-provisions a dashboard with 6 panels: All Events, VIP Access Alerts, OPA Denials, Unmask
Requests, Errors & Warnings, Billing Backend Requests.

---

### Remaining gaps for production

**Secrets management**  
Client secrets and admin passwords are hardcoded for demo convenience. In production, inject
via a secrets manager (Vault, AWS Secrets Manager, etc.) and rotate regularly. The Keycloak
admin password, partner client secret, and PostgreSQL credentials are the highest-priority items.

**TLS everywhere**  
All internal service-to-service calls (Kong→OPA, Kong→CRM, Admin→Postgres, Kong→Keycloak JWKS)
and external endpoints use plain HTTP. In production, terminate TLS at Kong and use mutual TLS
for internal east-west traffic.

**Rate limiting and CSRF**  
Kong has no rate-limit plugin configured. The Admin GUI has no CSRF protection. Add Kong's
`rate-limiting` plugin and CSRF tokens to the admin service before exposing to a wider network.

**Input validation**  
Customer IDs and MSISDN values are passed to CRM/Billing as-is. Add allow-list validation in
the Kong pre-function before constructing upstream URLs.

**High availability**  
The stack is single-instance. For production, run Kong in DB-backed cluster mode, replicate
Postgres with streaming replication, and deploy OPA as a sidecar or replicated service behind
a load balancer.

**Backend MSISDN resolution caching**  
Kong calls CRM `/api/resolve?msisdn=` synchronously on every MSISDN-based request. For billing
subscribers the lookup is best-effort (`customer_id=""` → treated as non-VIP). Cache this in
Kong's shared dictionary (`kong.cache`) to reduce CRM latency impact.
