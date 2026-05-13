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
| midPoint | evolveum/midpoint:4.8 | IGA — authoritative for user role assignments and app role governance |
| Loki | grafana/loki:3.7.1 | Log aggregation (TSDB schema v13) |
| Grafana | grafana/grafana:12.4.0 | Log dashboards |

### Key Files
- `kong/kong.yml` — Lua pre/post-function plugins: JWT RS256 verification, OPA call, response masking, audit log
- `opa/policy.rego` — Rego v1 (`import rego.v1`), entry point is `data.data_masking.decision`
- `opa/opa-config.yaml` — Bundle polling from admin-service every 15–60 s
- `admin-service/app.py` — Serves `/bundle/masking_config.tar.gz`; manages customer tiers, role masks, app registry, user lifecycle; midPoint write-through for app roles + user role read-back
- `admin-service/templates/` — Flask/Jinja2 UI: dashboard, tiers, roles, backends, apps, users
- `keycloak/realm-config.json` — Realm `demo`, clients, roles, users
- `postgres/init.sql` — Creates `admindb` + `adminuser`; must `GRANT ALL ON SCHEMA public`
- `grafana/loki-config.yaml` — Loki 3.x TSDB config (BoltDB removed in 3.0)
- `midpoint/` — midPoint home directory mount; `config/config.xml` if custom config needed

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
- OPA rule: `app_role_allowed` passes if backend has no registered role list (open) OR `input.role` is in the allowed list
- `effective_allow = allow AND app_role_allowed`
- Admin UI at `/apps` — register apps, set allowed roles per app, syncs to OPA bundle

### User Lifecycle (Keycloak + midPoint)
- Admin-service calls Keycloak Admin REST API using `admin-cli` client with master-realm credentials
- Env vars required: `KEYCLOAK_INTERNAL_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD`
- **Onboard**: POST `/users` → assign initial role via role-mappings API
- **Role change**: DELETE existing role-mappings + POST new set (atomic replacement) in Keycloak; best-effort PUT to midPoint UserType to sync governance record
- **Offboard**: PUT `/users/{id}` with `{"enabled": false}` — immediately invalidates all active tokens
- Admin UI at `/users`
- **midPoint role authority**: `/users` page reads role state from midPoint (`_mp_user_roles()`); falls back to Keycloak if midPoint unavailable; shows source badge (MP/KC) per user

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

### Admin-service DB Tables
| Table | Purpose |
|-------|---------|
| `customer_tiers` | customer_id → tier (vip/premium/risk/standard) |
| `role_field_masks` | role × field pairs that should be masked |
| `backends` | backend registry (id, name, url) |
| `field_mappings` | backend field → canonical field alias mapping |
| `apps` | registered applications (id, name, upstream_url, mp_oid) |
| `app_roles` | app_id × role — which roles may access each app |
| `sync_log` | audit trail of OPA bundle sync events |

### midPoint IGA Integration

**App role governance (ServiceType write-through)**
- Every app registered in admin-service (`/apps`) creates a midPoint `ServiceType` object with `name=app_id` and `subtype[]=allowed_roles`
- OID returned from midPoint is stored in `apps.mp_oid` for subsequent updates
- CRUD ops: `_mp_create_service`, `_mp_update_service_roles`, `_mp_delete_service`
- Cache: `_mp_cache` (TTL 300 s); `_mp_invalidate()` clears on any mutation
- midPoint REST endpoint: `{MIDPOINT_URL}/midpoint/ws/rest/services`

**User role state (UserType read-back)**
- `/users` page reads role assignments from midPoint `UserType.assignment[].targetRef` where `type=RoleType`
- `_mp_roles_map()` fetches all midPoint RoleType objects → `{role_name: oid}` (used for OID↔name translation)
- `_mp_user_roles()` caches `{username: [role_names]}` + `{username: oid}` for 120 s
- On role save: Keycloak write first (always) then `_mp_save_user_roles()` (best-effort PUT to midPoint)
- `_mp_save_user_roles()`: fetches current user, preserves non-RoleType assignments, replaces RoleType assignments, strips `version` field to avoid optimistic-lock conflict on PUT

**Environment variables**
- `MIDPOINT_URL` — internal Docker URL, default `http://midpoint:8080`
- `MIDPOINT_ADMIN_USER` — default `administrator`
- `MIDPOINT_ADMIN_PASS` — default `Admin123!`; set to `5ecr3t` in docker-compose for this project

**midPoint REST API quirks**
- Response envelope: `{"object": {"object": [...]}}` for collections; single object: `{"object": {...}}`
- `name` field may be `{"orig": "...", "norm": "..."}` dict or plain string — always check with `isinstance`
- `subtype` on ServiceType may be string or list — normalize with `isinstance(subtypes, str)` check
- `assignment` on UserType may be single dict or list — normalize similarly

### midPoint Certification Campaigns

Access certification (access reviews) is configured in midPoint UI at `http://localhost:8090`.

**Creating a campaign:**
1. Go to **Certification → Campaigns → New Campaign**
2. Choose **Role membership certification** scope: select the roles you want to review (e.g., all privileged roles: `admin`, `fraud_analyst`, `compliance_officer`)
3. Set **Reviewer**: manager of each user, or a specific reviewer (e.g., the compliance officer user)
4. Set **Deadline**: recommended 14 days for privileged roles, 30 days for standard
5. **Stage configuration**:
   - Stage 1: line manager reviews — `ACCEPT / REVOKE / NO_DECISION`
   - Stage 2 (optional): second reviewer (e.g., data_admin) escalation for `NO_DECISION` items
6. **Remediation**: set to **Revoke role** — midPoint removes the assignment and (via provisioning) triggers Keycloak role removal

**Recertification triggers (recommended):**
- Schedule automatic quarterly campaigns for privileged roles
- Trigger immediate campaign when: user changes department, user gets new privileged role, SoD policy detects conflict

**Certification for partner roles:**
- Scope: `b2b_partner`, `mvno_partner`, `partner` roles; reviewer = contract owner
- Shorter deadline (7 days) — partner access should be time-bounded

**Viewing results:**
- **Certification → Campaigns → [campaign name] → Cases**: lists all user×role pairs with reviewer decisions
- Export to CSV for compliance evidence

### midPoint Approval Workflows (Role Request)

midPoint approval workflows gate role assignments via the Policy rules + Workflow engine.

**Setting up a role request workflow:**
1. Open midPoint UI → **Repository Objects → Roles**
2. Select the target role (e.g., `fraud_analyst`)
3. Go to **Policy** tab → **Approval**
4. Add **Approver**: choose `Manager of user` or a specific user (e.g., `compliance_officer` account)
5. Add a second approver stage if SoD or privileged role (e.g., `data_admin`)
6. Save — all future assignments to this role trigger the approval workflow

**Role request flow:**
```
User (or admin) requests role assignment
    → midPoint creates WorkItem for stage-1 approver
    → Approver logs in at http://localhost:8090 → My Work Items → Approve/Reject
    → If approved (all stages): assignment activates, provisioning to Keycloak runs
    → If rejected: no assignment created; requester notified
```

**Configuring in XML (for automation/IaC):**
```xml
<approvalSchema>
  <stage>
    <number>1</number>
    <name>Manager approval</name>
    <approverRelation>org:manager</approverRelation>
    <outcomeIfNoApprovers>REJECT</outcomeIfNoApprovers>
  </stage>
  <stage>
    <number>2</number>
    <name>Compliance approval</name>
    <approverRef oid="<compliance-officer-oid>" type="UserType"/>
  </stage>
</approvalSchema>
```
Apply via midPoint REST: `POST /midpoint/ws/rest/roles/{oid}` with the modified role XML.

**SoD (Segregation of Duties):**
1. **Repository Objects → Roles → [role A]** → **Inducements** → **Policy Rules** → Add **Mutual Exclusion** with role B
2. midPoint blocks assignment if user already holds the conflicting role; generates a SoD violation report under **Reports → SoD violations**

**Time-limited access (JIT):**
1. When assigning a role, set **Validity** on the assignment: `activeTo = now + 8h`
2. midPoint auto-revokes and deprovisions from Keycloak when `activeTo` passes
3. For admin-service integration: `users_roles_save()` could pass `validTo` timestamp in `_mp_save_user_roles()` via `activation.validTo` field on the assignment object

### Development Branch
Always develop on `claude/midpoint-integration` and push there.
