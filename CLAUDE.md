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
- `kong/kong.yml` — Lua pre/post-function plugins: JWT RS256 verification, OPA call, response masking, audit log
- `opa/policy.rego` — Rego v1 (`import rego.v1`), entry point is `data.data_masking.decision`
- `opa/opa-config.yaml` — Bundle polling from admin-service every 15–60 s
- `admin-service/app.py` — Serves `/bundle/masking_config.tar.gz`; manages customer tiers, role masks, app registry, dynamic rules, user lifecycle (Keycloak Admin API)
- `admin-service/templates/` — Flask/Jinja2 UI: dashboard, tiers, roles, backends, apps, rules, users
- `frontend-hub/app.py` — Multi-app OAuth portal; lazy OAuth client registration; authlib 1.3.1 ID-token parse errors caught and recovered via `oa.token` fallback
- `keycloak/realm-config.json` — Realm `demo`, clients, roles, users
- `postgres/init.sql` — Creates `admindb` + `adminuser`; must `GRANT ALL ON SCHEMA public`
- `grafana/loki-config.yaml` — Loki 3.x TSDB config (BoltDB removed in 3.0)

### OPA Policy Rules
- Kong queries `/v1/data/data_masking/decision` (not the package root)
- `decision` uses `effective_allow` (not `allow` directly) — combines customer-tier gate AND app-role gate
- All sub-rules carry `default` values; `decision` is an explicit complete rule (avoids OPA v1.x package-document absence for default-only rules)
- Bundle `.manifest` must scope roots to `["masking_config"]` — without it OPA 1.x claims the entire `data` namespace and silently prevents `policy.rego` from loading
- OPA image: `openpolicyagent/opa:1.16.1-debug` — no `--v0-compatible` flag; native `import rego.v1` syntax only

### Customer Tier System (ABAC)
Four tiers replace the old boolean VIP flag. Tier is looked up from `data.masking_config.customer_tiers[input.customer_id]`; unassigned customers default to `standard`.

| Tier | Who can access |
|------|---------------|
| `standard` | All standard + privileged + partner roles |
| `premium` | care_l2+, supervisors, billing, roaming, audit + all privileged |
| `vip` | Privileged roles only (vip_agent, admin, fraud_analyst, compliance_officer, vip_care, data_admin) |
| `risk` | fraud_analyst, compliance_officer, care_supervisor, data_admin, admin only |

VIP access still requires `X-Access-Reference` header (Kong enforces, logs alert).

### Application Registry
- `apps` table in admin-service DB; role grants stored in `app_roles` table
- Included in OPA bundle as `data.masking_config.app_roles: {app_id: [roles]}`
- OPA rule: `app_role_allowed` passes if app has no registered role list (open) OR `input.role` is in the allowed list
- `effective_allow = allow AND app_role_allowed`
- Admin UI at `/apps` — register apps, set allowed roles per app, syncs to OPA bundle
- `input.app_id` = JWT `azp` claim (Keycloak `client_id`) — Kong extracts and sends to OPA
- **Per-app masking**: use dynamic rules with `condition_apps` to add/remove field masking for specific apps (see Dynamic Rule Engine)

### User Lifecycle (Keycloak Admin API)
- Admin-service calls Keycloak Admin REST API using `admin-cli` client with master-realm credentials
- Env vars required: `KEYCLOAK_INTERNAL_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`
- **Onboard**: POST `/users` → assign initial role via role-mappings API
- **Role change**: DELETE existing role-mappings + POST new set (atomic replacement)
- **Offboard**: PUT `/users/{id}` with `{"enabled": false}` — immediately invalidates all active tokens
- Admin UI at `/users`

### Context Signals (ABAC)
Kong injects these into `input.ctx` for OPA. All have safe defaults if the header is absent.

| Header | OPA field | Default | Effect when set |
|--------|-----------|---------|-----------------|
| *(time-based)* | `in_working_hours` | `true` | care_l1/l2/billing_agent see less contact data out-of-hours |
| `X-Initiated-By` | `initiated_by` | `"customer"` | `"agent"` → care_l2 loses MSISDN visibility |
| `X-Channel` | `channel` | `"web"` | `"ivr"` → agent role masks name |
| `X-Session-Type` | `session_type` | `"normal"` | `"readonly"` → billing/care_l2 mask account_balance + bill_amount |
| `X-Purpose` | `purpose` | `""` | Logged in audit; no masking effect yet |

### JWT Verification (Kong Lua)
- JWKS fetched from `KEYCLOAK_INTERNAL_URL` (internal Docker URL, never the public URL)
- Issuer validated by realm-path check (`/realms/demo`), not hostname — works on localhost and Cloud Shell
- Key loaded from `jwk.x5c[1]` (DER cert) to avoid OpenSSL 3.x JWK-alg constraint (`error:1C880004`)
- Signature verified via `resty.openssl.pkey:verify()` — bypasses lua-resty-jwt's OpenSSL 3.x incompatibility

### Roles & Masking (summary)
Full matrix managed in admin-service UI at `/roles`. Key role groups:

| Group | Roles | Default masked fields |
|-------|-------|-----------------------|
| Privileged | vip_agent, admin, fraud_analyst, compliance_officer, vip_care, data_admin | none |
| Care | care_l1, care_l2, care_supervisor | decreasing set from L1→supervisor |
| Standard | agent, supervisor, billing_agent, noc_operator, field_technician, roaming_ops, audit_viewer | role-specific subsets |
| Partners | partner, b2b_partner, mvno_partner | most PII fields; standard tier only |

### Dynamic Rule Engine
Stored in `masking_rules` table. Rules evaluated in priority order (lower number first). Conditions are AND-ed; empty list in any condition = matches all.

| Condition field | Type | Matches |
|----------------|------|---------|
| `condition_roles` | `TEXT[]` | `input.role` |
| `condition_tiers` | `TEXT[]` | `customer_tier` |
| `condition_purposes` | `TEXT[]` | `X-Purpose` header |
| `condition_channels` | `TEXT[]` | `X-Channel` header |
| `condition_apps` | `TEXT[]` | `input.app_id` (JWT `azp`) |
| `condition_in_working_hours` | `BOOLEAN\|NULL` | time check; NULL = any |

Actions: `mask` (add fields to masked set) or `unmask` (remove from masked set). `unmask` overrides `mask` when both match the same field.

OPA helpers: `_roles_match`, `_tiers_match`, `_purposes_match`, `_channels_match`, `_apps_match`, `_wh_matches` — all follow same pattern: empty collection passes, non-empty checks membership.

Admin UI at `/rules`. DB column `condition_apps` added via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` on startup (safe for existing installs).

### Activity Catalog (Role → Activity → Field)
Implements business-proposed role×activity→data-field mapping. Activities are named business operations (e.g. `fraud_investigation`, `billing_dispute`) that grant additional field visibility beyond the role baseline.

- DB: `activities` (catalog: activity_id, label, description) + `activity_field_policy` (activity_id × role × field)
- Bundle: `activity_policies: {activity_id: {role: [fields]}}` — unmask grants
- OPA: `_activity_unmasked` rule — when `input.ctx.purpose` matches an activity AND role has grants, those fields are removed from masked set
- Precedence: activity grants < dynamic-rule unmask < unmask token (all three can lift masking; role baseline + dynamic-rule mask can add masking)
- Admin UI at `/activities` — matrix view: rows=roles, columns=fields, checkbox per cell
- Additive with `purpose_policies`: both contribute to `_effective_masked` via separate OPA rules
- For MASK-on-activity (restrict for specific activity): use dynamic rules with `condition_purposes`

### Admin-service DB Tables
| Table | Purpose |
|-------|---------|
| `customer_tiers` | customer_id → tier (vip/premium/risk/standard) |
| `role_field_masks` | role × field pairs that should be masked |
| `backends` | backend registry (id, name, url) |
| `field_mappings` | backend field → canonical field alias mapping |
| `apps` | registered applications (id, name, upstream_url) |
| `app_roles` | app_id × role — which roles may access each app |
| `purpose_policies` | role × purpose × field — field exemptions by purpose (legacy; prefer activities) |
| `activities` | activity catalog: activity_id, label, description |
| `activity_field_policy` | activity_id × role × field — unmask grants per activity |
| `masking_rules` | dynamic rules: priority, conditions (roles/tiers/purposes/channels/apps/hours), action, fields |
| `sync_log` | audit trail of OPA bundle sync events |

### Frontend Hub (`:3001`)
- `frontend-hub/app.py` — Flask app; 5 static OAuth clients + dynamic discovery from admin-service `/api/apps` (5-min TTL cache)
- OAuth clients registered lazily via `_oa(app_key)` on first use; `_registered_oauth_keys` set prevents double-registration
- **authlib 1.3.1 gotcha**: `authorize_access_token()` calls `parse_id_token()` internally; if ID-token claim validation fails (nonce/at_hash mismatch, key issues), exception propagates even though the access-token exchange already succeeded. Fix: wrap in try/except and fall back to `oa.token` (stored in Flask `g` before validation runs). Userinfo is fetched separately via `requests.get(userinfo_endpoint)` anyway.
- `KEYCLOAK_URL` (public, browser-facing) vs `KEYCLOAK_INTERNAL_URL` (Docker-internal, used for token/userinfo/jwks endpoints)
- `GET /api/apps` on admin-service requires `X-Governance-API-Key` header

### Development Branch
Always develop on `claude/keycloak-kong-integration-yIVJ1` and push there.
