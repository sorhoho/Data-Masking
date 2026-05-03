# Solution Design Document
# PII Data Masking Gateway

| | |
|---|---|
| **Document version** | 1.0 |
| **Status** | Draft — pending ARB review |
| **Classification** | Internal — Confidential |
| **Author** | Engineering |
| **Date** | 2026-05-03 |
| **Review target** | Architecture Review Board |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Business Context](#2-business-context)
3. [Scope and Boundaries](#3-scope-and-boundaries)
4. [Solution Architecture](#4-solution-architecture)
5. [Component Design](#5-component-design)
6. [Data Classification and PII Handling](#6-data-classification-and-pii-handling)
7. [Authentication and Authorization Design](#7-authentication-and-authorization-design)
8. [Audit and Observability](#8-audit-and-observability)
9. [Software Version and End-of-Support Register](#9-software-version-and-end-of-support-register)
10. [Non-Functional Requirements](#10-non-functional-requirements)
11. [Architecture Decision Records](#11-architecture-decision-records)
12. [Gap Analysis and Remediation Plan](#12-gap-analysis-and-remediation-plan)
13. [Operational Readiness](#13-operational-readiness)
14. [Compliance Mapping](#14-compliance-mapping)
15. [Approval Sign-off](#15-approval-sign-off)

---

## 1. Executive Summary

This document describes the design of a **role-based PII data masking system** enforced at the
API gateway layer. The system intercepts all API requests carrying customer PII, applies
cryptographically verified identity (JWT RS256), evaluates masking policy via an external policy
engine (OPA), and returns masked responses appropriate to the caller's role — without modifying
the upstream services that own the data.

Key outcomes:
- PII is masked in transit at a single enforcement point (Kong gateway), not duplicated across services.
- Masking policy is live-configurable without code deployment or gateway restart.
- Every access to sensitive customer records is logged with full attribution and persisted in Loki.
- VIP customer data has an additional access-control gate (access reference header + real-time alert).

---

## 2. Business Context

### 2.1 Problem Statement

Customer-facing backend APIs (CRM, Billing) return raw PII fields (name, MSISDN, national ID,
address, location) to every authenticated caller regardless of role. This creates three risks:

1. **Overprivileged access** — a call-centre agent can read fields they do not need to perform
   their job (e.g. national ID, exact address).
2. **VIP customer exposure** — high-profile customers have no stronger protection than standard
   customers despite regulatory and reputational requirements.
3. **No audit trail** — there is no centralised record of who accessed which customer's data.

### 2.2 Regulatory and Policy Drivers

| Obligation | Relevance |
|---|---|
| Personal Data Protection Act (PDPA) | Requires data minimisation — callers should only receive data necessary for their role |
| Internal Data Classification Policy | L1 (direct identifiers) and L2 (profiling data) must have access controls |
| VIP Customer Protection Policy | VIP customer data requires additional access control and logging |
| Internal Audit Policy | All PII access must be logged with user attribution for 90 days minimum |

### 2.3 Stakeholders

| Stakeholder | Interest |
|---|---|
| Operations (Ops) | Manage VIP list and masking rules without engineering involvement |
| Security | Ensure PII is not leaked to lower-privilege roles |
| Compliance / Legal | Evidence of data minimisation and audit trail |
| Engineering | No changes to upstream CRM and Billing services |
| IT EA | Architecture alignment, technology standards, supportability |

---

## 3. Scope and Boundaries

### 3.1 In Scope

- Masking of PII fields in CRM and Billing API responses.
- Role-based access control using Keycloak-issued JWT tokens.
- VIP customer access gate with mandatory access reference and real-time alerting.
- Live policy management via Admin GUI.
- Persistent audit logging via Loki.

### 3.2 Out of Scope

- Masking of PII in request bodies (only response bodies are masked).
- Encryption at rest for the PostgreSQL database (infrastructure concern).
- Integration with enterprise SIEM (Splunk / Sentinel) — listed as P2 gap.
- Mobile application layer — this design covers backend API calls only.

### 3.3 Trust Boundary Diagram

```
────────────────────── EXTERNAL ZONE ───────────────────────
  Browser / API Client
    │  HTTPS (TLS — P1 gap: currently HTTP in dev)
    ▼
────────────────────── DMZ / GATEWAY ZONE ───────────────────
  Kong Gateway :8000          Keycloak :8080
    │  (JWKS fetch, JWT verify)     │
    │◄──────────────────────────────┘
    │
────────────────────── INTERNAL TRUSTED ZONE ────────────────
    ├─► OPA :8181           (policy evaluation)
    ├─► CRM Mock :5000      (raw PII — port not exposed)
    ├─► Billing Mock :5001  (raw PII — port not exposed)
    ├─► Log Dashboard :9000 → Loki :3100 → Grafana :3001
    └─► Admin Service :8888 → PostgreSQL :5432
              ▲
    OPA bundle poll (every 15–60 s)
```

---

## 4. Solution Architecture

### 4.1 Architecture Overview

The system is composed of nine containerised services orchestrated by Docker Compose (target:
Kubernetes). All PII-bearing API traffic passes through Kong gateway. No PII is returned to
callers until Kong has applied the masking policy returned by OPA.

```
Client → Kong → (JWKS verify) → OPA decision → Upstream service → Masked response → Client
                                       ↑
                            Admin Service (bundle) ← PostgreSQL
                                       ↓ audit
                            Log Dashboard → Loki → Grafana
```

### 4.2 Request Lifecycle (Abbreviated)

1. Client presents a Bearer JWT to Kong.
2. Kong fetches JWKS from Keycloak (5-min per-worker cache) and verifies RS256 signature,
   expiry, and issuer.
3. Kong extracts the highest-priority role from `realm_access.roles`.
4. For MSISDN-based routes, Kong calls CRM `/api/resolve` to obtain `customer_id`.
5. Kong calls OPA with `{role, username, path, method, customer_id, backend}`.
6. OPA evaluates policy against the masking config bundle (polled from Admin Service).
7. If `allow=false` → 403. If VIP and missing access reference → 400.
8. Kong forwards the request to the upstream service and buffers the response.
9. Kong applies two-pass masking (canonical fields, then backend aliases) using the
   `masked_fields` list returned by OPA.
10. Kong fires an async audit event to Log Dashboard.
11. Masked response returned to client.

---

## 5. Component Design

### 5.1 Kong Gateway

| Attribute | Value |
|---|---|
| Version | 3.9.1 (EOS: OSS "use latest" policy; Enterprise 3.10 LTS EOS Mar 2028) |
| Mode | DB-less (declarative `kong.yml`) |
| Plugins | `cors`, `pre-function` (Lua), `post-function` (Lua) |
| JWT verification | `resty.jwt` + `resty.openssl.pkey` — RS256, JWKS, 5-min cache |
| OPA call | Synchronous HTTP POST to `http://opa:8181/v1/data/data_masking` |
| Masking | In-memory Lua — two passes, no upstream data modification |
| Audit log | Async HTTP POST (fire-and-forget) to Log Dashboard |

The Kong Admin API (`:8001`) must not be externally reachable. It is currently mapped to
`127.0.0.1:8001` in `docker-compose.yml` and should be removed from host-port mapping in production.

### 5.2 Keycloak

| Attribute | Value |
|---|---|
| Version | 26.6.1 (community rolling support — only latest minor receives patches) |
| Realm | `demo` — auto-imported from `keycloak/realm-config.json` |
| Token type | RS256-signed JWT containing `realm_access.roles` |
| Persistence | PostgreSQL (`keycloak` database) |
| Clients | `website-client` (auth code flow), `partner-client` (client credentials / M2M) |

### 5.3 OPA (Open Policy Agent)

| Attribute | Value |
|---|---|
| Version | v1.4.2 (pinned; OPA monthly releases, no formal EOL policy) |
| Rego compatibility | `--v0-compatible` flag — existing `policy.rego` runs unchanged under OPA v1.x |
| Policy | `opa/policy.rego` — role × field matrix, VIP check, backend alias lookup |
| Config distribution | Bundle mode — polls `http://admin-service:8888/bundle/masking_config.tar.gz` every 15–60 s |
| Decision logging | `decision_logs.console: true` — every evaluation emitted as structured JSON to stdout |

OPA runs as a sidecar-style service. Because it uses bundle mode, it never loses config on
restart — the Admin Service serves the current config on the next poll.

### 5.4 Admin Service

| Attribute | Value |
|---|---|
| Framework | Flask 3.x |
| Database | PostgreSQL 16 via psycopg2-binary |
| Tables | `fields`, `vip_customers`, `role_masked_fields`, `backends`, `field_mappings`, `sync_log` |
| Bundle endpoint | `GET /bundle/masking_config.tar.gz` — gzip tarball with `masking_config/data.json` |
| Authentication | HTTP Basic Auth — `admin / admin123` (P1 gap: change before production) |

### 5.5 PostgreSQL

Single PostgreSQL 16 instance shared by Keycloak and Admin Service:

| Database | Owner | Purpose |
|---|---|---|
| `keycloak` | `postgres` | Keycloak realm, users, sessions |
| `admindb` | `adminuser` | Masking policy, VIP list, audit/sync log |

Created by `postgres/init.sql` on first volume initialisation.

### 5.6 Log Dashboard → Loki → Grafana

| Component | Role |
|---|---|
| Log Dashboard | Receives SSE events from Kong; forwards each to Loki (daemon thread, 1 s timeout); serves real-time `/stream` SSE to browser |
| Loki | Persists structured log streams; queryable via LogQL |
| Grafana | Pre-provisioned dashboard: All Events, VIP Alerts, OPA Denials, Unmask Requests, Errors, Billing Requests |

---

## 6. Data Classification and PII Handling

### 6.1 Field Classification

| Field (canonical) | Class | Sensitivity | Masking function |
|---|:---:|---|---|
| `name` | L1 | Direct identifier | First char of each word kept |
| `msisdn` | L1 | Direct identifier | Country prefix + last 2 digits kept |
| `email` | L1 | Direct identifier | First + last char of local part kept |
| `national_id` | L1 | Direct identifier | First 2 chars kept |
| `address` | L1 | Direct identifier | Full redact `*** (redacted)` |
| `last_call_duration` | L2 | Profiling / linkable | Full redact `***` |
| `data_roaming_gb` | L2 | Profiling / linkable | Full redact `***` |
| `last_location` | L2 | Profiling / linkable | Full redact `***` |

### 6.2 PII in Audit Logs

The audit event sent to Log Dashboard and Loki contains:

- `customer_id` (e.g. `C002`) — opaque identifier, not PII
- `msisdn_hint` — last 4 digits only (e.g. `5432`) — logged for traceability, not full MSISDN
- `role`, `username`, `path`, `backend`, `opa_decision`, `masked_field_count`
- `access_reference` — ticket number supplied by caller for VIP access

Full PII values (name, MSISDN, national_id) are **never** written to audit logs.

### 6.3 Data Flow Map (PII)

```
CRM / Billing (raw PII)
    │
    ▼ (internal network only — ports not host-exposed)
Kong post-function
    │  PII masked in memory
    ▼
Client (masked values only)

Kong audit event
    │  customer_id + msisdn_hint (no raw PII)
    ▼
Log Dashboard → Loki (persisted, no raw PII)
```

---

## 7. Authentication and Authorization Design

### 7.1 User Authentication (Human Callers)

```
Browser → Website :3000
              │  OIDC auth-code flow
              ▼
         Keycloak :8080 (RS256 JWT)
              │  Bearer token on every API call
              ▼
         Kong :8000 → JWKS verify → role extracted
```

### 7.2 Machine-to-Machine Authentication (Partner)

```
Partner System → Keycloak :8080
                     │  client_credentials grant
                     │  client_id=partner-client, client_secret=<secret>
                     ▼
                 RS256 JWT (role=partner)
                     │
                 Kong :8000 → JWKS verify
```

### 7.3 Role Matrix

| Role | VIP access | Unmask | L1 fields | L2 fields |
|---|:---:|:---:|:---:|:---:|
| `agent` | Denied (403) | Denied (403) | All masked | All masked |
| `supervisor` | Denied (403) | Allowed | msisdn + national_id masked | All clear |
| `vip_agent` | Allowed + access reference | Denied (403) | All clear | All clear |
| `admin` | Allowed + access reference | Allowed | All clear | All clear |
| `partner` | Denied (403) | Denied (403) | All masked | All masked |

### 7.4 JWT Verification Detail

Kong pre-function performs full RS256 verification:

1. Parse JWT header to extract `kid`.
2. Fetch JWKS from `http://keycloak:8080/realms/demo/protocol/openid-connect/certs`.
3. Cache JWKS per Kong worker for 5 minutes (`kong.cache:get("jwks_v1", {ttl=300})`).
4. On unknown `kid`, invalidate cache and re-fetch once (handles Keycloak key rotation).
5. Convert matching JWK to PEM using `resty.openssl.pkey`.
6. Call `resty.jwt:verify_jwt_obj` with `valid_issuers={KEYCLOAK_ISSUER}` and
   `lifetime_grace_period=10`.
7. Reject with 401 on any failure.

---

## 8. Audit and Observability

### 8.1 Audit Events

Every request through Kong generates an audit event:

| Field | Description |
|---|---|
| `event` | `api_request`, `vip_access_alert`, `unmask_request`, `subscription_request` |
| `service` | `kong` |
| `level` | `info`, `warn`, `error` |
| `timestamp` | UTC HH:MM:SS |
| `username` | From JWT `preferred_username` |
| `role` | Effective role |
| `customer_id` | Opaque customer identifier |
| `backend` | `crm` or `billing` |
| `opa_decision` | `ALLOW` or `DENY` |
| `masked_field_count` | Number of fields masked |
| `is_vip` | Boolean |
| `access_reference` | Ticket number (VIP access only) |

### 8.2 Log Pipeline

```
Kong → POST /log → Log Dashboard
                        │  in-memory ring buffer (last 500)
                        │  fire-and-forget → Loki
                        ▼
                   Grafana (pre-built dashboard)
```

### 8.3 Grafana Dashboard Panels

| Panel | LogQL filter |
|---|---|
| All Events | `{job="data-masking"} \| json` |
| VIP Access Alerts | `event=\`vip_access_alert\`` |
| OPA Denials | `opa_decision=\`DENY\`` |
| Unmask Requests | `event=\`unmask_request\`` |
| Errors & Warnings | `level=~\`warn\|error\`` |
| Billing Backend | `backend=\`billing\`` |

### 8.4 OPA Decision Logging

OPA emits every policy evaluation as structured JSON to stdout (`decision_logs.console: true`).
These are captured by the container runtime and available in `docker logs opa` or via a
log aggregator. Decision logs contain: decision_id, input, result, timestamp, path.

---

## 9. Software Version and End-of-Support Register

All component versions are reviewed at design time against vendor support lifecycle policies.
This register must be reviewed before each major deployment and at minimum annually.

| Component | Version | Support Status (May 2026) | EOL / EOS Date | Next Review |
|---|---|---|---|---|
| Kong Gateway (OSS) | 3.9.1 | Active — OSS "use latest" policy; no per-minor EOS | Rolling (upgrade to latest 3.x quarterly) | Aug 2026 |
| Keycloak | 26.6.1 | Active — community rolling support (latest minor only) | Rolling (upgrade within 6 months of new major) | Aug 2026 |
| OPA | v1.4.2 | Active — monthly releases, no formal EOL | Rolling (review quarterly) | Aug 2026 |
| PostgreSQL | 16 | **Supported** — active bug-fix + security | **Oct 2028** | Oct 2027 |
| Grafana Loki | 3.7.1 | Active — 2-minor rolling support window | Rolling | Aug 2026 |
| Grafana | 12.4.0 | Active — supported until ~May 2027 | **~May 2027** | Nov 2026 |
| Python | 3.12-slim | Active — bug-fix + security | **Oct 2028** | Oct 2027 |
| Flask | 3.1.1 | Active | Follows Python lifecycle | Oct 2027 |
| psycopg2-binary | ≥ 2.9 | Active | N/A | Oct 2027 |
| authlib | 1.3.1 | Active | N/A | Oct 2027 |

### Version history (this document)

| Date | Action | Previous → New |
|---|---|---|
| 2026-05-03 | Initial version alignment | Kong 3.5→3.9.1, Keycloak 23.0→26.6.1, OPA latest→v1.4.2, Loki 2.9.0→3.7.1, Grafana 10.3.0→12.4.0, Python 3.11→3.12 |

### Vendor support policies

| Vendor | Policy summary | Reference |
|---|---|---|
| Kong (OSS) | Only the latest minor release is supported. No per-version EOL dates. Enterprise LTS versions (3.7, 3.9, 3.10) have 2–3 year windows. | developer.konghq.com/gateway/version-support-policy |
| Keycloak | Community: latest minor only. Red Hat Build of Keycloak (RHBK) offers 18–36 month support per major. | keycloak.org |
| OPA | No formal EOL policy. Monthly releases. Pin to a specific version; review quarterly. | openpolicyagent.org |
| PostgreSQL | 5-year support from initial release. Minor-version bugfixes only. | postgresql.org/support/versioning |
| Grafana | Latest + previous minor supported. Major versions: current + one back. | grafana.com/docs/release-life-cycle |
| Python | 5-year lifecycle per minor: 1.5 yr bug-fix, then 3.5 yr security-only. | devguide.python.org/versions |

---

## 10. Non-Functional Requirements


| NFR | Requirement | Current State | Gap |
|---|---|---|---|
| **Availability** | 99.9% uptime for gateway | Single-instance Kong, OPA, Postgres | HA not implemented — P2 |
| **Response time** | < 200 ms added latency at gateway | JWKS cached; OPA call synchronous (~5 ms local) | Acceptable for PoC |
| **Throughput** | 500 req/s per Kong node | Not load-tested | Load test required before production |
| **Security — transport** | All traffic TLS | HTTP only (dev environment) | TLS — P1 gap |
| **Security — secrets** | Secrets in vault, not env vars | Hardcoded client secrets | Secrets manager — P1 gap |
| **Auditability** | 90-day log retention | Loki with local volume | Loki retention policy + backup — P2 |
| **Recoverability** | RPO ≤ 1h, RTO ≤ 4h | No backup configured | Postgres backup — P2 |
| **Scalability** | Horizontal Kong scaling | Single node | Kong cluster mode — P2 |
| **Observability** | Metrics + logs + traces | Logs only (Loki) | Prometheus metrics — P3 |

---

## 11. Architecture Decision Records

### ADR-001: JWT Verification at Gateway Layer

**Status**: Accepted

**Context**: JWT tokens issued by Keycloak need to be verified on every API request. Options:
(A) each upstream service verifies independently; (B) gateway verifies once.

**Decision**: Gateway (Kong) verifies RS256 signature via JWKS. Upstreams receive only
pre-verified requests.

**Rationale**: Centralised enforcement — no risk of an upstream skipping verification.
JWKS caching at the Kong worker level avoids a Keycloak round-trip on every request.

**Consequences**: If Kong pre-function has a bug, all requests are affected. Mitigated by unit
tests and the fact that `resty.jwt` is a well-maintained library.

---

### ADR-002: OPA as Policy Engine

**Status**: Accepted

**Context**: Masking rules (which fields to mask per role) change at operational cadence, not
engineering cadence. Options: (A) hard-code in Kong Lua; (B) external policy engine.

**Decision**: OPA with `policy.rego` — rules expressed as code, evaluated at runtime.

**Rationale**: Ops can change the role × field matrix via the Admin GUI without touching code
or restarting Kong. Policy is auditable (version-controlled `.rego` file).

**Consequences**: Synchronous OPA call adds ~5 ms latency per request on the local network.
Acceptable for the current throughput requirements.

---

### ADR-003: OPA Bundle Mode over Push API

**Status**: Accepted

**Context**: OPA needs masking config at startup and after every admin change. Options:
(A) Admin Service pushes to `PUT /v1/data/masking_config` on every change; (B) OPA polls
a bundle endpoint.

**Decision**: Bundle mode — Admin Service serves `GET /bundle/masking_config.tar.gz`; OPA
polls every 15–60 seconds.

**Rationale**: Push mode loses state on OPA restart (requires explicit re-sync). Bundle mode
is self-healing — OPA re-fetches on startup automatically. Decision logging integrates
natively with bundle mode.

**Trade-off**: Up to 60 s propagation delay after an admin change (acceptable for policy
updates; not a low-latency requirement).

---

### ADR-004: PostgreSQL for Admin Service and Keycloak

**Status**: Accepted

**Context**: Original PoC used SQLite for admin-service. Options: (A) retain SQLite;
(B) migrate to PostgreSQL shared with Keycloak.

**Decision**: PostgreSQL 16, single instance, separate databases (`keycloak`, `admindb`).

**Rationale**: Keycloak requires a proper RDBMS for production. Sharing one Postgres instance
reduces operational overhead for a PoC-to-pilot migration. `psycopg2` provides proper
parameterised queries, preventing SQL injection.

**Consequences**: Single Postgres instance is a single point of failure — accepted risk for
PoC. Production requires Postgres HA (streaming replication or managed RDS/Cloud SQL).

---

### ADR-005: Audit Log Pipeline (Loki + Grafana)

**Status**: Accepted

**Context**: Audit events from Kong need to be persisted beyond the container lifecycle.
Options: (A) write to file; (B) push to Loki; (C) push to enterprise SIEM directly.

**Decision**: Log Dashboard forwards to Loki; Grafana pre-provisions dashboards. Enterprise
SIEM integration deferred to P2.

**Rationale**: Loki is lightweight and integrates natively with Grafana. Fire-and-forget
forwarding (1 s timeout, exception swallowed) means a Loki failure never affects the gateway
request path. Enterprise SIEM integration can be added as a Loki export rule without changing
any application code.

---

## 12. Gap Analysis and Remediation Plan

### P1 — Blocking (must resolve before production go-live)

| ID | Gap | Current state | Required action |
|---|---|---|---|
| P1-01 | TLS on all service endpoints | Plain HTTP | Terminate TLS at Kong; use mTLS for Kong→OPA, OPA→Admin, Admin→Postgres |
| P1-02 | Secrets in vault, not env vars | Client secrets + DB passwords hardcoded | Integrate Vault or cloud secrets manager; rotate all secrets |
| P1-03 | Admin GUI authentication | HTTP Basic Auth, hardcoded `admin/admin123` | Replace with Keycloak-backed OIDC login + RBAC; enforce MFA for admin role |
| P1-04 | OPA bundle integrity | Bundle served over plain HTTP, no signature | Sign bundle with OPA `--bundle` key; verify signature in OPA config |
| P1-05 | CSRF protection on Admin GUI | No CSRF tokens | Add Flask-WTF CSRF tokens to all state-changing forms |

### P2 — Time-boxed (resolve within 90 days of go-live)

| ID | Gap | Required action |
|---|---|---|
| P2-01 | Single-instance PostgreSQL | Postgres streaming replication or managed RDS; configure automated backups |
| P2-02 | Single-instance Kong | Kong DB-backed cluster mode or Kong Ingress Controller on Kubernetes |
| P2-03 | Rate limiting | Add Kong `rate-limiting` plugin (per-consumer + global) |
| P2-04 | Input validation | Allow-list customer IDs and MSISDN format in Kong pre-function before upstream URL construction |
| P2-05 | Loki retention policy | Configure Loki compaction (90-day retention per policy obligation) + object storage backend |
| P2-06 | Enterprise SIEM integration | Add Loki → Splunk/Sentinel export rule |
| P2-07 | Kong Admin API exposure | Remove host-port binding for `:8001`; access only via bastion or internal network |

### P3 — Accepted risk (document and review annually)

| ID | Gap | Rationale for deferral |
|---|---|---|
| P3-01 | MSISDN resolution caching | CRM latency acceptable at current scale; add `kong.cache` caching when p99 > 50 ms |
| P3-02 | Prometheus metrics | Logs provide sufficient observability for current scale |
| P3-03 | Loki audit log tamper protection | Loki is internal; P1-01 (TLS) reduces risk of in-transit tampering |

---

## 13. Operational Readiness

### 12.1 Runbook Summary

| Scenario | Action |
|---|---|
| OPA loses masking config | OPA auto-recovers on next bundle poll (≤ 60 s). No manual action needed. |
| Keycloak restart | Website retries automatically (`restart: on-failure`). No manual action. |
| PostgreSQL restart | Admin Service and Keycloak reconnect automatically. |
| Add/remove VIP customer | Admin GUI → VIP page → save. OPA picks up within 60 s. |
| Change masking rules | Admin GUI → Masking Rules → save. OPA picks up within 60 s. |
| Audit log investigation | Grafana :3001 → Data Masking dashboard → filter by `customer_id` or `username`. |
| Force OPA re-poll | Restart OPA container — it polls immediately on startup. |

### 12.2 Startup Dependencies

```
postgres (healthy)
  ├─► keycloak → website
  └─► admin-service (healthy)
        └─► opa → kong

loki (healthy) → log-dashboard → crm-mock, billing-mock, kong
grafana (auto-provisions on start)
```

### 12.3 Backup and Recovery

| Component | Backup required | Method |
|---|---|---|
| PostgreSQL | Yes — P2 | `pg_dump` daily + WAL archiving to object storage |
| OPA policy.rego | Yes | Version-controlled in git |
| Kong kong.yml | Yes | Version-controlled in git |
| Keycloak realm-config.json | Yes | Version-controlled in git |
| Loki logs | Yes — P2 | Loki object storage backend (S3/GCS) |

---

## 14. Compliance Mapping

| Requirement | How addressed |
|---|---|
| **PDPA: Data minimisation** | Role × field matrix enforced at gateway — callers receive only fields their role permits |
| **PDPA: Purpose limitation** | `/api/unmask` path requires explicit `X-Unmask-Reason` header; reason logged |
| **PDPA: Accountability** | Every access logged with username, role, customer_id, timestamp, OPA decision |
| **VIP Protection Policy** | VIP flag enforced by OPA; access requires `X-Access-Reference`; real-time alert fired |
| **Internal Audit Policy** | Audit trail in Loki; Grafana dashboards for investigation; 90-day retention (P2) |
| **Data Classification Policy** | L1/L2 fields classified, masking functions applied per class |

---

## 15. Approval Sign-off

| Role | Name | Decision | Date |
|---|---|---|---|
| Solution Architect | | | |
| IT Security | | | |
| Data Protection Officer | | | |
| IT Enterprise Architecture | | | |
| Application Owner | | | |

**Conditions of approval** (to be completed by ARB):

- [ ] P1-01 TLS implemented before production deployment
- [ ] P1-02 Secrets management solution agreed and implemented
- [ ] P1-03 Admin GUI authentication replaced with enterprise SSO
- [ ] P1-04 OPA bundle signing implemented
- [ ] P1-05 CSRF protection implemented
- [ ] P2 items assigned to owners with agreed delivery dates
- [ ] DPIA completed and signed by DPO
