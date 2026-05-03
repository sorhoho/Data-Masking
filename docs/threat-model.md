# Threat Model — PII Data Masking Gateway
# STRIDE Analysis

| | |
|---|---|
| **Document version** | 1.0 |
| **Methodology** | STRIDE |
| **Status** | Draft |
| **Date** | 2026-05-03 |
| **Scope** | All trust boundaries and data flows in the data masking stack |

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Assets and Trust Boundaries](#2-assets-and-trust-boundaries)
3. [Data Flow Diagram](#3-data-flow-diagram)
4. [STRIDE Threat Register](#4-stride-threat-register)
   - [S — Spoofing](#s--spoofing)
   - [T — Tampering](#t--tampering)
   - [R — Repudiation](#r--repudiation)
   - [I — Information Disclosure](#i--information-disclosure)
   - [D — Denial of Service](#d--denial-of-service)
   - [E — Elevation of Privilege](#e--elevation-of-privilege)
5. [Risk Summary](#5-risk-summary)
6. [Residual Risk Register](#6-residual-risk-register)

---

## 1. System Overview

The data masking gateway intercepts API calls carrying customer PII, verifies the caller's
identity (JWT RS256 via Keycloak JWKS), evaluates masking policy (OPA), and returns a masked
response. The policy is managed via an Admin GUI backed by PostgreSQL and distributed to OPA
as a bundle.

**Key security properties this model assesses:**

1. Only cryptographically verified identities can call protected APIs.
2. Role determines exactly which PII fields are visible — policy is externally auditable.
3. VIP customer data has an additional access gate.
4. Every access is logged with full attribution.
5. The masking policy itself cannot be silently altered.

---

## 2. Assets and Trust Boundaries

### 2.1 Assets

| Asset | Sensitivity | Location |
|---|---|---|
| Customer PII (name, MSISDN, national_id, email, address) | Critical | CRM / Billing backends |
| JWT access tokens | High | In transit (browser → Kong) |
| Keycloak JWKS (public keys) | Medium | Keycloak :8080 |
| OPA masking policy bundle | High | Admin Service → OPA |
| PostgreSQL masking config (role matrix, VIP list) | High | PostgreSQL :5432 |
| Audit logs | Medium | Loki :3100 |
| Admin GUI credentials | High | Environment / secret store |
| Partner client secret | High | Environment / secret store |

### 2.2 Trust Boundaries

| Boundary | From | To | Protocol |
|---|---|---|---|
| TB-01 | External client | Kong :8000 | HTTP (P1 gap: should be HTTPS) |
| TB-02 | Kong | Keycloak :8080 (JWKS) | HTTP (P1 gap) |
| TB-03 | Kong | OPA :8181 | HTTP (internal) |
| TB-04 | Kong | CRM Mock :5000 | HTTP (internal, port not host-exposed) |
| TB-05 | Kong | Billing Mock :5001 | HTTP (internal, port not host-exposed) |
| TB-06 | Kong | Log Dashboard :9000 | HTTP (internal) |
| TB-07 | OPA | Admin Service :8888 | HTTP (bundle poll, internal) |
| TB-08 | Admin Service | PostgreSQL :5432 | TCP (internal) |
| TB-09 | Log Dashboard | Loki :3100 | HTTP (internal) |
| TB-10 | Grafana | Loki :3100 | HTTP (internal) |
| TB-11 | Admin user | Admin GUI :8888 | HTTP (P1 gap: should be HTTPS + SSO) |

---

## 3. Data Flow Diagram

```
[External]
  Client ──TB-01──► Kong :8000
                      │
                      ├──TB-02──► Keycloak :8080  (JWKS fetch, cached)
                      │
                      ├──TB-03──► OPA :8181        (policy eval)
                      │               ▲
                      │         TB-07 │ (bundle poll)
                      │         Admin Service :8888
                      │               │ TB-08
                      │         PostgreSQL :5432
                      │
                      ├──TB-04──► CRM Mock :5000   (raw PII)
                      ├──TB-05──► Billing Mock :5001 (raw PII)
                      │
                      └──TB-06──► Log Dashboard :9000
                                        │ TB-09
                                   Loki :3100
                                        ▲ TB-10
                                   Grafana :3001

[Admin user] ──TB-11──► Admin GUI :8888
```

---

## 4. STRIDE Threat Register

Severity levels: **Critical** / **High** / **Medium** / **Low**  
Status: **Open** / **Mitigated** / **Accepted**

---

### S — Spoofing

Attacker claims an identity they do not own.

---

**S-01: Forged or replayed JWT**

| | |
|---|---|
| **Threat** | Attacker presents a self-signed, expired, or replayed JWT claiming an elevated role (e.g. `admin`) |
| **Target** | Kong pre-function (TB-01) |
| **Severity** | Critical |
| **Status** | Mitigated |
| **Mitigation** | Kong verifies RS256 signature against Keycloak JWKS. Without the Keycloak private key, a forged token fails verification. `lifetime_grace_period=10s` and expiry check prevent replay of expired tokens. |
| **Residual risk** | If Keycloak private key is compromised — out of scope for this model (key compromise = full IdP breach). |

---

**S-02: JWKS endpoint impersonation (DNS / ARP spoofing)**

| | |
|---|---|
| **Threat** | Attacker intercepts the Kong → Keycloak JWKS fetch (TB-02) and returns a JWKS with attacker-controlled keys. All subsequent JWTs signed by the attacker's key would be accepted. |
| **Target** | TB-02 (Kong → Keycloak JWKS fetch) |
| **Severity** | Critical |
| **Status** | Open — **P1 gap** |
| **Mitigation** | None currently. Requires TLS on TB-02 with certificate pinning or CA verification. |
| **Required action** | Implement TLS for all internal service-to-service calls; verify Keycloak's TLS certificate against a trusted CA in the Kong pre-function JWKS fetch. |

---

**S-03: Admin GUI impersonation**

| | |
|---|---|
| **Threat** | Attacker claims admin identity to modify VIP list or masking rules |
| **Target** | TB-11 (Admin GUI :8888) |
| **Severity** | High |
| **Status** | Partially mitigated — **P1 gap** |
| **Mitigation** | HTTP Basic Auth (`admin/admin123`) is required. Password is hardcoded and transmitted over plain HTTP. |
| **Required action** | Replace with Keycloak-backed OIDC login. Enforce MFA for admin role. Add HTTPS on TB-11. |

---

**S-04: OPA bundle source impersonation**

| | |
|---|---|
| **Threat** | Attacker intercepts OPA's bundle poll (TB-07) and returns a malicious bundle granting all roles access to all fields with VIP list emptied |
| **Target** | TB-07 (OPA → Admin Service bundle poll) |
| **Severity** | Critical |
| **Status** | Open — **P1 gap** |
| **Mitigation** | None. Bundle is served over plain HTTP with no signature verification. |
| **Required action** | TLS on TB-07; sign bundle with OPA `--bundle` signing key; configure OPA to verify bundle signature. |

---

### T — Tampering

Attacker modifies data at rest or in transit.

---

**T-01: JWT payload modification**

| | |
|---|---|
| **Threat** | Attacker intercepts JWT in transit and modifies `realm_access.roles` to claim a higher role |
| **Target** | TB-01 (client → Kong) |
| **Severity** | Critical |
| **Status** | Mitigated |
| **Mitigation** | RS256 signature covers the header and payload. Any modification invalidates the signature. |

---

**T-02: OPA masking policy tampering in transit**

| | |
|---|---|
| **Threat** | MITM attacker modifies the bundle response between Admin Service and OPA during polling |
| **Target** | TB-07 |
| **Severity** | Critical |
| **Status** | Open — **P1 gap** |
| **Mitigation** | None — plain HTTP, no bundle signature. |
| **Required action** | TLS + OPA bundle signing (see S-04). |

---

**T-03: PostgreSQL masking config tampering**

| | |
|---|---|
| **Threat** | Attacker with internal network access connects to PostgreSQL :5432 and modifies `role_masked_fields` or `vip_customers` tables |
| **Target** | PostgreSQL :5432 (TB-08) |
| **Severity** | High |
| **Status** | Partially mitigated |
| **Mitigation** | PostgreSQL is on the internal Docker network; not host-exposed. `adminuser` has limited privileges (`GRANT ALL ON DATABASE admindb` — P2: scope down to table-level grants). |
| **Residual risk** | Any container on the same Docker network can reach :5432. Network segmentation (Docker network isolation per tier) recommended. |

---

**T-04: Kong declarative config (`kong.yml`) tampering**

| | |
|---|---|
| **Threat** | Attacker modifies `kong.yml` to remove pre-function (disabling masking) or alter JWKS URL |
| **Target** | Kong config at rest |
| **Severity** | Critical |
| **Status** | Mitigated (at rest) |
| **Mitigation** | `kong.yml` is version-controlled in git. Changes require a deployment pipeline approval. Kong Admin API (:8001) is mapped to `127.0.0.1` only. |
| **Residual risk** | Kong Admin API should have the host-port binding removed entirely in production (see P2-07). |

---

**T-05: Audit log tampering**

| | |
|---|---|
| **Threat** | Attacker deletes or modifies Loki log entries to cover their tracks |
| **Target** | Loki :3100 |
| **Severity** | Medium |
| **Status** | Accepted — **P3** |
| **Mitigation** | Loki is on the internal network; not host-exposed. Loki does not support in-place log editing (immutable append model). |
| **Residual risk** | Loki data volume can be deleted if attacker has Docker host access. Object storage backend (P2-05) with write-once policy would eliminate this. |

---

### R — Repudiation

Actor denies performing an action.

---

**R-01: User denies accessing VIP customer record**

| | |
|---|---|
| **Threat** | Agent/vip_agent claims they never accessed a VIP customer |
| **Target** | Audit trail |
| **Severity** | High |
| **Status** | Mitigated |
| **Mitigation** | Every VIP access fires a `vip_access_alert` event containing `username`, `role`, `customer_id`, `access_reference`, and `timestamp`. Event persists in Loki. |

---

**R-02: Admin denies changing masking policy**

| | |
|---|---|
| **Threat** | Admin user claims they did not change a masking rule or VIP list |
| **Target** | Admin GUI change audit |
| **Severity** | High |
| **Status** | Partially mitigated |
| **Mitigation** | `sync_log` table in PostgreSQL records every config push with timestamp. |
| **Residual risk** | `sync_log` records the sync event, not which specific field changed. Consider adding a change-diff audit log per table row (e.g. PostgreSQL trigger or application-level change log). |

---

**R-03: OPA denies making a decision**

| | |
|---|---|
| **Threat** | Policy team disputes the decision OPA made for a specific request |
| **Target** | OPA decision log |
| **Severity** | Medium |
| **Status** | Mitigated |
| **Mitigation** | `decision_logs.console: true` emits every evaluation with `decision_id`, `input`, `result`, and `timestamp` to stdout, captured by Docker logs and Loki. |

---

### I — Information Disclosure

Attacker gains access to data they are not authorised to see.

---

**I-01: PII intercepted in transit (no TLS)**

| | |
|---|---|
| **Threat** | Attacker on the network intercepts HTTP traffic between client and Kong (:8000) and reads raw PII in request/response bodies |
| **Target** | TB-01 |
| **Severity** | Critical |
| **Status** | Open — **P1 gap** |
| **Required action** | TLS on all external-facing endpoints (TB-01, TB-11). |

---

**I-02: PII in error messages**

| | |
|---|---|
| **Threat** | Error responses include raw field values (e.g. OPA input echoed back on 403) |
| **Target** | Kong pre-function error paths |
| **Severity** | Medium |
| **Status** | Mitigated |
| **Mitigation** | Kong error responses return only structured error messages (`{"error":true,"message":"..."}`) — no PII fields, no OPA input echo, no stack traces. |

---

**I-03: Full PII in audit logs**

| | |
|---|---|
| **Threat** | Audit logs in Loki contain raw PII, creating a second high-risk data store |
| **Target** | Loki log pipeline |
| **Severity** | High |
| **Status** | Mitigated |
| **Mitigation** | Audit events log `customer_id` (opaque), `msisdn_hint` (last 4 digits only), username, role — no raw name, full MSISDN, national_id, address, or email. |

---

**I-04: OPA decision logs expose sensitive context**

| | |
|---|---|
| **Threat** | OPA decision logs contain `customer_id` + full input (role, path, backend) — readable by anyone with access to container logs or Loki |
| **Target** | OPA stdout → Docker logs |
| **Severity** | Low |
| **Status** | Accepted |
| **Mitigation** | `customer_id` is an opaque identifier. Input does not contain PII field values. Access to Docker logs and Loki should be restricted to security/ops roles (access control on Grafana — P2). |

---

**I-05: Admin GUI exposes full masking config without session timeout**

| | |
|---|---|
| **Threat** | Admin GUI session left open; unauthorised person modifies VIP list or masking rules |
| **Target** | Admin GUI :8888 |
| **Severity** | High |
| **Status** | Open — **P1 gap** |
| **Required action** | Keycloak-backed OIDC login with session timeout (15 min idle). |

---

**I-06: PostgreSQL accessible from all containers on the Docker network**

| | |
|---|---|
| **Threat** | Any container on the internal Docker network can connect to PostgreSQL :5432 and read the masking config or Keycloak user data |
| **Target** | PostgreSQL (TB-08) |
| **Severity** | High |
| **Status** | Partially mitigated |
| **Mitigation** | PostgreSQL is not host-exposed. `pg_hba.conf` restricts to the Docker subnet. |
| **Residual risk** | Any compromised container can reach Postgres. Use Docker network segmentation (separate networks per tier) in production. |

---

### D — Denial of Service

Attacker disrupts availability.

---

**D-01: Request flood (no rate limiting)**

| | |
|---|---|
| **Threat** | Attacker floods Kong :8000 with requests, exhausting OPA, CRM, or Billing capacity |
| **Target** | Kong, OPA, upstream services |
| **Severity** | High |
| **Status** | Open — **P2 gap** |
| **Required action** | Add Kong `rate-limiting` plugin — per-consumer limit (e.g. 100 req/min for agents) and global limit. |

---

**D-02: JWKS cache exhaustion via unknown `kid`**

| | |
|---|---|
| **Threat** | Attacker sends a stream of JWTs with random `kid` values, causing Kong to invalidate and re-fetch JWKS on every request, overwhelming Keycloak |
| **Target** | Keycloak JWKS endpoint (TB-02) |
| **Severity** | Medium |
| **Status** | Partially mitigated |
| **Mitigation** | Kong `kong.cache:get` with 5-min TTL limits cache invalidation. However, a single unknown `kid` triggers an immediate re-fetch. |
| **Residual risk** | At high volume, each unique `kid` triggers a Keycloak call. Mitigate by adding a failed-kid counter: after N misses within T seconds, return 401 without re-fetching. Rate limiting (D-01) reduces exposure. |

---

**D-03: Admin Service bundle endpoint overload**

| | |
|---|---|
| **Threat** | Attacker (or misconfigured OPA) floods `GET /bundle/masking_config.tar.gz`, overwhelming the Admin Service |
| **Target** | Admin Service :8888 (TB-07) |
| **Severity** | Low |
| **Status** | Accepted — **P3** |
| **Mitigation** | OPA bundle polling is configured at 15–60 s intervals — not continuous. Admin Service is on the internal network. |

---

**D-04: Log Dashboard memory exhaustion**

| | |
|---|---|
| **Threat** | Attacker floods the `/log` endpoint, filling the in-memory ring buffer |
| **Target** | Log Dashboard :9000 |
| **Severity** | Low |
| **Status** | Mitigated |
| **Mitigation** | `deque(maxlen=500)` — oldest entries are evicted when the buffer is full. Memory footprint is bounded. |

---

### E — Elevation of Privilege

Attacker gains more access than authorised.

---

**E-01: Role claim in JWT bypasses masking**

| | |
|---|---|
| **Threat** | Attacker self-assigns `admin` or `vip_agent` role by crafting a JWT with elevated `realm_access.roles` |
| **Target** | Kong pre-function |
| **Severity** | Critical |
| **Status** | Mitigated |
| **Mitigation** | RS256 signature covers `realm_access.roles`. Modification invalidates the signature. Roles are assigned only by Keycloak admin. |

---

**E-02: Admin GUI accessible without MFA**

| | |
|---|---|
| **Threat** | Attacker with stolen admin password gains full control of masking policy and VIP list |
| **Target** | Admin GUI :8888 |
| **Severity** | High |
| **Status** | Open — **P1 gap** |
| **Required action** | Keycloak OIDC login with MFA enforced for admin role. Remove hardcoded HTTP Basic Auth. |

---

**E-03: SQL injection in Admin Service**

| | |
|---|---|
| **Threat** | Attacker injects SQL via Admin GUI form fields to read/modify PostgreSQL data directly |
| **Target** | Admin Service → PostgreSQL |
| **Severity** | High |
| **Status** | Mitigated |
| **Mitigation** | All queries use `psycopg2` parameterised statements (`%s` placeholders). No string concatenation in SQL. `UniqueViolation` and other exceptions are caught without exposing SQL details. |

---

**E-04: Partner bypasses VIP access control**

| | |
|---|---|
| **Threat** | Partner (M2M client) accesses a VIP customer's data despite being excluded from VIP access |
| **Target** | OPA policy |
| **Severity** | High |
| **Status** | Mitigated |
| **Mitigation** | OPA `allow` rule for `partner` explicitly includes `not vip_customers[input.customer_id]`. Partner cannot access VIP records regardless of path or method. |

---

**E-05: Partner accesses `/api/unmask` endpoint**

| | |
|---|---|
| **Threat** | Partner calls `/api/unmask/*` to retrieve unmasked PII |
| **Target** | OPA policy |
| **Severity** | High |
| **Status** | Mitigated |
| **Mitigation** | OPA `allow` rule for `partner` includes `not startswith(input.path, "/api/unmask")`. Partner receives 403 on unmask paths. |

---

**E-06: Malicious OPA bundle grants elevated access**

| | |
|---|---|
| **Threat** | Attacker with MITM position (see S-04) serves a bundle that grants all roles `masked_fields=[]` and empties the VIP list, effectively disabling all masking |
| **Target** | OPA policy data (masking_config bundle) |
| **Severity** | Critical |
| **Status** | Open — **P1 gap** |
| **Required action** | TLS + OPA bundle signing (see S-04 / T-02). |

---

## 5. Risk Summary

| ID | Category | Threat summary | Severity | Status |
|---|---|---|---|---|
| S-01 | Spoofing | Forged / replayed JWT | Critical | Mitigated |
| S-02 | Spoofing | JWKS endpoint impersonation | Critical | **Open P1** |
| S-03 | Spoofing | Admin GUI impersonation | High | **Open P1** |
| S-04 | Spoofing | OPA bundle source impersonation | Critical | **Open P1** |
| T-01 | Tampering | JWT payload modification | Critical | Mitigated |
| T-02 | Tampering | OPA bundle tampering in transit | Critical | **Open P1** |
| T-03 | Tampering | PostgreSQL config tampering | High | Partial |
| T-04 | Tampering | `kong.yml` tampering | Critical | Mitigated |
| T-05 | Tampering | Audit log tampering | Medium | Accepted P3 |
| R-01 | Repudiation | Deny VIP access | High | Mitigated |
| R-02 | Repudiation | Deny policy change | High | Partial |
| R-03 | Repudiation | Deny OPA decision | Medium | Mitigated |
| I-01 | Info Disclosure | PII intercepted in transit | Critical | **Open P1** |
| I-02 | Info Disclosure | PII in error messages | Medium | Mitigated |
| I-03 | Info Disclosure | PII in audit logs | High | Mitigated |
| I-04 | Info Disclosure | OPA decision log exposure | Low | Accepted |
| I-05 | Info Disclosure | Admin GUI session exposure | High | **Open P1** |
| I-06 | Info Disclosure | PostgreSQL accessible internally | High | Partial |
| D-01 | DoS | Request flood — no rate limiting | High | **Open P2** |
| D-02 | DoS | JWKS cache exhaustion | Medium | Partial |
| D-03 | DoS | Bundle endpoint overload | Low | Accepted P3 |
| D-04 | DoS | Log Dashboard memory exhaustion | Low | Mitigated |
| E-01 | EoP | Role claim bypass | Critical | Mitigated |
| E-02 | EoP | Admin GUI without MFA | High | **Open P1** |
| E-03 | EoP | SQL injection | High | Mitigated |
| E-04 | EoP | Partner bypasses VIP control | High | Mitigated |
| E-05 | EoP | Partner accesses unmask path | High | Mitigated |
| E-06 | EoP | Malicious OPA bundle | Critical | **Open P1** |

---

## 6. Residual Risk Register

Items accepted or partially mitigated that require explicit sign-off:

| ID | Risk | Owner | Acceptance condition |
|---|---|---|---|
| T-03 residual | Postgres accessible from all containers | Infrastructure | Docker network segmentation implemented in production |
| T-05 (P3) | Loki logs can be deleted via Docker host access | Security | Object storage backend with write-once policy (P2-05) |
| I-04 | OPA decision logs readable by log access holders | Security | Grafana access control restricted to ops/security roles |
| I-06 residual | Postgres reachable from any container | Infrastructure | Network segmentation before production |
| D-02 residual | JWKS cache thrashing under targeted attack | Engineering | Rate limiting (D-01) reduces exposure; accepted until P2-03 |
| R-02 residual | Sync log records event, not diff | Engineering | Change-diff audit log added before production |
