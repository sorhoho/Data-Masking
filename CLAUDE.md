# Data-Masking Project — Claude Guidelines

## Behavioral Guidelines (Karpathy-inspired)

**Core Principle:** Caution over speed. Merge with the project-specific rules below.

### 1. Think Before Coding
"Don't assume. Don't hide confusion. Surface tradeoffs."
State assumptions explicitly, present multiple interpretations rather than choosing silently, and surface simpler alternatives when available.

### 2. Simplicity First
"Minimum code that solves the problem. Nothing speculative."
Avoid unrequested features, single-use abstractions, premature flexibility, or error handling for impossible scenarios.

### 3. Surgical Changes
"Touch only what you must. Clean up only your own mess."
Preserve existing style, avoid unrelated improvements, and only remove imports or functions your changes made obsolete — not pre-existing dead code.

### 4. Goal-Driven Execution
"Define success criteria. Loop until verified."
Transform abstract tasks into testable objectives with clear verification steps before writing any code.

---

## Project-Specific Context

### Stack
| Component | Image / Version | Role |
|-----------|----------------|------|
| Keycloak | quay.io/keycloak/keycloak:26.6.1 | OIDC identity provider — realm `demo` |
| Kong | kong:3.9.1 | API gateway — JWT verification + OPA enforcement |
| OPA | openpolicyagent/opa:1.16.1-debug | Policy engine — bundle mode, native v1 Rego |
| PostgreSQL | postgres:16 | Shared DB for Keycloak + admin-service |
| Loki | grafana/loki:3.7.1 | Log aggregation (TSDB schema v13) |
| Grafana | grafana/grafana:12.4.0 | Log dashboards |

### Key Files
- `kong/kong.yml` — Lua pre/post-function plugins: JWT RS256 verification, OPA call, response masking
- `opa/policy.rego` — Rego v1 (`import rego.v1`), entry point is `data.data_masking.decision`
- `opa/opa-config.yaml` — Bundle polling from admin-service every 15–60 s
- `admin-service/app.py` — Serves `/bundle/masking_config.tar.gz`; manages VIP list + role masks
- `keycloak/realm-config.json` — Realm `demo`, clients, roles, users
- `postgres/init.sql` — Creates `admindb` + `adminuser`; must `GRANT ALL ON SCHEMA public`
- `grafana/loki-config.yaml` — Loki 3.x TSDB config (BoltDB removed in 3.0)

### OPA Policy Rules
- Kong queries `/v1/data/data_masking/decision` (not the package root)
- `decision` is an explicit complete rule — avoids the OPA v1.x behaviour where `default`-only values are absent from package-document query results
- All sub-rules (`allow`, `is_vip`, `masked_fields`, `backend_fields`) carry `default` values

### JWT Verification (Kong Lua)
- JWKS fetched from `KEYCLOAK_INTERNAL_URL` (internal Docker URL, never the public URL)
- Issuer validated by realm-path check (`/realms/demo`), not hostname — works on localhost and Cloud Shell
- Key loaded from `jwk.x5c[1]` (DER cert) to avoid OpenSSL 3.x JWK-alg constraint (`error:1C880004`)
- Signature verified via `resty.openssl.pkey:verify()` — bypasses lua-resty-jwt's OpenSSL 3.x incompatibility

### Roles & Masking
| Role | Masked fields | VIP access |
|------|--------------|------------|
| agent | name, msisdn, email, national_id, address, L2 fields | No |
| supervisor | msisdn, national_id | No |
| vip_agent | none | Yes (X-Access-Reference required) |
| admin | none | Yes |
| partner | same as agent | No |

### Development Branch
Always develop on `claude/keycloak-kong-integration-yIVJ1` and push there.
