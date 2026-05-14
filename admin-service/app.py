import io
import json
import os
import tarfile
import time
import requests
import psycopg2
import psycopg2.extras
import psycopg2.errors
from datetime import datetime
from functools import wraps
from flask import (Flask, make_response, render_template, request, redirect,
                   url_for, session, flash, jsonify)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "admin-secret-key")

OPA_URL      = os.environ.get("OPA_URL",        "http://opa:8181")
ADMIN_USER   = os.environ.get("ADMIN_USER",     "admin")
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "admin123")
DATABASE_URL = os.environ.get("DATABASE_URL",
               "postgresql://adminuser:admin_pass@postgres:5432/admindb")

KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM        = os.environ.get("KEYCLOAK_REALM",         "demo")
KEYCLOAK_ADMIN_USER   = os.environ.get("KEYCLOAK_ADMIN_USER",    "admin")
KEYCLOAK_ADMIN_PASS   = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")

GOVERNANCE_API_KEY  = os.environ.get("GOVERNANCE_API_KEY", "governance-internal-key")
UNMASK_REASON_CODES = ["FRAUD_INVESTIGATION", "COMPLIANCE_AUDIT", "LEGAL_HOLD",
                       "CUSTOMER_DISPUTE", "TECHNICAL_ESCALATION", "REGULATOR_REQUEST"]

MIDPOINT_URL        = os.environ.get("MIDPOINT_URL",        "http://midpoint:8080")
MIDPOINT_ADMIN_USER = os.environ.get("MIDPOINT_ADMIN_USER", "administrator")
MIDPOINT_ADMIN_PASS = os.environ.get("MIDPOINT_ADMIN_PASS", "Admin123!")
MP_CACHE_TTL        = 300   # seconds — app-roles cache
MP_USER_CACHE_TTL   = 120   # seconds — user-roles cache (shorter, more dynamic)

# Ordered list of (field, classification) — drives both DB and UI
FIELDS = [
    ("name",               "L1"),
    ("msisdn",             "L1"),
    ("email",              "L1"),
    ("national_id",        "L1"),
    ("address",            "L1"),
    ("last_call_duration", "L2"),
    ("data_roaming_gb",    "L2"),
    ("last_location",      "L2"),
]
UNMASK_FIELDS = [f for f, _ in FIELDS]
ROLES = [
    # Legacy
    "agent", "supervisor", "vip_agent", "admin", "partner",
    # Care Operations
    "care_l1", "care_l2", "care_supervisor",
    # Technical Operations
    "noc_operator", "field_technician", "roaming_ops",
    # Business Operations
    "billing_agent", "fraud_analyst", "compliance_officer",
    # Audit
    "audit_viewer",
    # VIP
    "vip_care",
    # External Partners
    "b2b_partner", "mvno_partner",
    # Administration
    "data_admin",
]

PURPOSES = [
    "fraud_investigation",
    "compliance_audit",
    "billing_dispute",
    "technical_escalation",
    "regulator_request",
    "legal_hold",
]

TIERS    = ["standard", "premium", "vip", "risk"]
CHANNELS = ["web", "ivr", "mobile", "api"]

_DEFAULT_RULES = [
    # (priority, name, roles, tiers, purposes, channels, in_working_hours, action, fields)
    (1,  "VIP tier: roaming_ops can see location + data",
     ["roaming_ops"], ["vip"], [], [], None, "unmask",
     ["last_location", "data_roaming_gb"]),
    (5,  "Premium fraud investigation: care_l2 full PII unmask",
     ["care_l2"], ["premium"], ["fraud_investigation"], [], None, "unmask",
     ["national_id", "address", "last_location"]),
    (10, "Risk tier + out of hours: extra contact masking",
     [], ["risk"], [], [], False, "mask",
     ["msisdn", "email"]),
    (20, "Billing dispute on premium: billing_agent sees national_id",
     ["billing_agent"], ["premium"], ["billing_dispute"], [], None, "unmask",
     ["national_id"]),
]

_DEFAULT_MASKS = [
    # ── Legacy roles ──────────────────────────────────────────────────────────
    ("agent", "name"), ("agent", "msisdn"), ("agent", "email"),
    ("agent", "national_id"), ("agent", "address"),
    ("agent", "last_call_duration"), ("agent", "data_roaming_gb"),
    ("agent", "last_location"),
    ("supervisor", "msisdn"), ("supervisor", "national_id"),
    ("partner", "name"), ("partner", "msisdn"), ("partner", "email"),
    ("partner", "national_id"), ("partner", "address"),
    ("partner", "last_call_duration"), ("partner", "data_roaming_gb"),
    ("partner", "last_location"),
    # ── Care L1: name visible, everything else masked ─────────────────────────
    ("care_l1", "msisdn"), ("care_l1", "email"), ("care_l1", "national_id"),
    ("care_l1", "address"), ("care_l1", "last_call_duration"),
    ("care_l1", "data_roaming_gb"), ("care_l1", "last_location"),
    # ── Care L2: contact visible, PII/L2 masked ───────────────────────────────
    ("care_l2", "national_id"), ("care_l2", "address"),
    ("care_l2", "last_call_duration"), ("care_l2", "data_roaming_gb"),
    ("care_l2", "last_location"),
    # ── Care Supervisor: national_id and location masked ──────────────────────
    ("care_supervisor", "national_id"), ("care_supervisor", "last_location"),
    # ── NOC: network data visible, identity masked ────────────────────────────
    ("noc_operator", "name"), ("noc_operator", "email"),
    ("noc_operator", "national_id"), ("noc_operator", "address"),
    ("noc_operator", "last_call_duration"),
    # ── Field Technician: name/MSISDN/address/location visible ───────────────
    ("field_technician", "email"), ("field_technician", "national_id"),
    ("field_technician", "last_call_duration"), ("field_technician", "data_roaming_gb"),
    # ── Roaming Ops: MSISDN + roaming visible ────────────────────────────────
    ("roaming_ops", "name"), ("roaming_ops", "email"),
    ("roaming_ops", "national_id"), ("roaming_ops", "address"),
    ("roaming_ops", "last_call_duration"),
    # ── Billing Agent: charges + name/MSISDN visible ─────────────────────────
    ("billing_agent", "email"), ("billing_agent", "national_id"),
    ("billing_agent", "address"), ("billing_agent", "last_location"),
    # ── Audit Viewer: all masked ──────────────────────────────────────────────
    ("audit_viewer", "name"), ("audit_viewer", "msisdn"), ("audit_viewer", "email"),
    ("audit_viewer", "national_id"), ("audit_viewer", "address"),
    ("audit_viewer", "last_call_duration"), ("audit_viewer", "data_roaming_gb"),
    ("audit_viewer", "last_location"),
    # ── B2B Partner: name visible, all else masked ────────────────────────────
    ("b2b_partner", "msisdn"), ("b2b_partner", "email"),
    ("b2b_partner", "national_id"), ("b2b_partner", "address"),
    ("b2b_partner", "last_call_duration"), ("b2b_partner", "data_roaming_gb"),
    ("b2b_partner", "last_location"),
    # ── MVNO Partner: MSISDN + roaming visible ────────────────────────────────
    ("mvno_partner", "name"), ("mvno_partner", "email"),
    ("mvno_partner", "national_id"), ("mvno_partner", "address"),
    ("mvno_partner", "last_call_duration"), ("mvno_partner", "last_location"),
    # fraud_analyst, compliance_officer, vip_care, data_admin: nothing masked
]

_DEFAULT_TIERS = [
    ("C001", "vip",  "Initial VIP – seeded on first run"),
    ("C004", "vip",  "Initial VIP – seeded on first run"),
]

VALID_TIERS = ["standard", "premium", "vip", "risk"]

_DEFAULT_BACKENDS = [
    ("crm",     "CRM System",      "http://crm-mock:5000",     "Main CRM — field names are canonical"),
    ("billing", "Billing System",  "http://billing-mock:5001", "Billing backend — aliased field names"),
]

_DEFAULT_FIELD_MAPPINGS = [
    ("crm", "name",               "name",               "L1"),
    ("crm", "msisdn",             "msisdn",             "L1"),
    ("crm", "email",              "email",              "L1"),
    ("crm", "national_id",        "national_id",        "L1"),
    ("crm", "address",            "address",            "L1"),
    ("crm", "last_call_duration", "last_call_duration", "L2"),
    ("crm", "data_roaming_gb",    "data_roaming_gb",    "L2"),
    ("crm", "last_location",      "last_location",      "L2"),
    ("billing", "mobilenum",        "msisdn",             "L1"),
    ("billing", "subname",          "name",               "L1"),
    ("billing", "ic_num",           "national_id",        "L1"),
    ("billing", "billing_address",  "address",            "L1"),
    ("billing", "call_duration_s",  "last_call_duration", "L2"),
    ("billing", "roaming_gb",       "data_roaming_gb",    "L2"),
]

# App ID = Keycloak client_id (azp JWT claim). Must match exactly.
_DEFAULT_APPS = [
    ("agent-portal",         "Agent Portal",          "", "Care agent & billing web app"),
    ("supervisor-dashboard", "Supervisor Dashboard",   "", "Team lead & supervisor UI"),
    ("fraud-console",        "Fraud Console",          "", "Fraud analyst investigation tool"),
    ("audit-viewer-app",     "Audit Viewer",           "", "Compliance read-only portal"),
    ("partner-api",          "Partner API",            "", "B2B/MVNO partner BFF"),
]

_DEFAULT_APP_ROLES = [
    # Agent Portal: front-line care + billing
    ("agent-portal", "agent"), ("agent-portal", "care_l1"), ("agent-portal", "care_l2"),
    ("agent-portal", "billing_agent"), ("agent-portal", "noc_operator"),
    ("agent-portal", "field_technician"), ("agent-portal", "roaming_ops"),
    # Supervisor Dashboard: supervisors + privileged ops
    ("supervisor-dashboard", "supervisor"), ("supervisor-dashboard", "care_supervisor"),
    ("supervisor-dashboard", "vip_agent"), ("supervisor-dashboard", "vip_care"),
    ("supervisor-dashboard", "admin"), ("supervisor-dashboard", "data_admin"),
    # Fraud Console: fraud & compliance only
    ("fraud-console", "fraud_analyst"), ("fraud-console", "compliance_officer"),
    ("fraud-console", "admin"), ("fraud-console", "data_admin"),
    # Audit Viewer: audit + compliance read access
    ("audit-viewer-app", "audit_viewer"), ("audit-viewer-app", "compliance_officer"),
    ("audit-viewer-app", "admin"),
    # Partner API: external partners only
    ("partner-api", "partner"), ("partner-api", "b2b_partner"), ("partner-api", "mvno_partner"),
]


# ── midPoint app-role cache + write helpers ───────────────────────────────────

_mp_cache: dict = {"service_oids": {}, "fetched_at": 0.0}
_mp_inducement_cache: dict = {"app_roles": None, "fetched_at": 0.0}
MP_INDUCEMENT_CACHE_TTL = 120  # seconds


def _mp_invalidate():
    _mp_cache["service_oids"] = {}
    _mp_cache["fetched_at"]   = 0.0


def _mp_invalidate_inducements():
    _mp_inducement_cache["app_roles"]   = None
    _mp_inducement_cache["fetched_at"] = 0.0


def _mp_service_oids_refresh():
    """Fetch all midPoint Service OIDs into cache. Used for delete/update lookups."""
    now = time.time()
    if _mp_cache["service_oids"] and now - _mp_cache["fetched_at"] < MP_CACHE_TTL:
        return
    try:
        r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/services",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
        raw_list = r.json().get("object", {}).get("object", [])
        if isinstance(raw_list, dict):
            raw_list = [raw_list]
        oids = {}
        for svc in raw_list:
            name = svc.get("name", "")
            if isinstance(name, dict):
                name = name.get("orig", "")
            oid = svc.get("oid", "")
            if name and oid:
                oids[name] = oid
        _mp_cache["service_oids"] = oids
        _mp_cache["fetched_at"]   = now
    except Exception:
        pass


def _mp_service_oid(app_id: str) -> str | None:
    """Return midPoint Service OID for app_id (refresh cache if stale)."""
    _mp_service_oids_refresh()
    return _mp_cache["service_oids"].get(app_id)


def _mp_create_service(app_id: str, name: str, description: str) -> str | None:
    """Create midPoint Service object (visibility/audit only — no role data). Returns OID."""
    if not app_id:
        app.logger.warning("_mp_create_service: empty app_id — skipping")
        return None
    try:
        r = requests.post(
            f"{MIDPOINT_URL}/midpoint/ws/rest/services",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"service": {
                "name":        app_id,
                "displayName": name or app_id,
                "description": description or "",
            }},
            timeout=10,
        )
        if r.status_code == 409:
            # Already exists — fetch OID from midPoint rather than treating as error
            app.logger.info(f"_mp_create_service {app_id}: already exists, fetching OID")
            _mp_invalidate()
            _mp_service_oids_refresh()
            return _mp_cache["service_oids"].get(app_id)
        if not r.ok:
            app.logger.warning(
                f"_mp_create_service {app_id}: {r.status_code} {r.text[:300].replace(chr(10), ' ')}"
            )
            return None
        location = r.headers.get("Location", "")
        oid = location.rstrip("/").split("/")[-1] if location else None
        _mp_invalidate()
        return oid
    except Exception as exc:
        app.logger.warning(f"_mp_create_service {app_id}: exception {exc}")
        return None


def _mp_update_service_meta(app_id: str) -> bool:
    """Update midPoint Service metadata (name/description) from DB. No role data."""
    oid = _mp_service_oid(app_id)
    if not oid:
        conn = get_db()
        row  = qone(conn, "SELECT mp_oid FROM apps WHERE app_id = %s", (app_id,))
        conn.close()
        oid  = (row.get("mp_oid") or "") if row else ""
    if not oid:
        return False
    try:
        conn = get_db()
        row  = qone(conn, "SELECT name, description FROM apps WHERE app_id = %s", (app_id,))
        conn.close()
        r = requests.put(
            f"{MIDPOINT_URL}/midpoint/ws/rest/services/{oid}",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Content-Type": "application/json"},
            json={"service": {
                "oid":         oid,
                "name":        app_id,
                "displayName": row["name"] if row else app_id,
                "description": (row["description"] if row else "") or "",
            }},
            timeout=10,
        )
        if not r.ok:
            app.logger.warning(
                f"_mp_update_service_meta {app_id}: {r.status_code} {r.text[:200].replace(chr(10), ' ')}"
            )
            return False
        _mp_invalidate()
        return True
    except Exception as exc:
        app.logger.warning(f"_mp_update_service_meta {app_id}: exception {exc}")
        return False


def _mp_delete_service(app_id: str) -> bool:
    """Delete midPoint Service object. Returns True on success or not-found."""
    oid = _mp_service_oid(app_id)
    if not oid:
        conn = get_db()
        row  = qone(conn, "SELECT mp_oid FROM apps WHERE app_id = %s", (app_id,))
        conn.close()
        oid = (row.get("mp_oid") or "") if row else ""
    if not oid:
        return True  # nothing to delete
    try:
        r = requests.delete(
            f"{MIDPOINT_URL}/midpoint/ws/rest/services/{oid}",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            timeout=10,
        )
        if r.status_code in (200, 204, 404):
            _mp_invalidate()
            return True
        r.raise_for_status()
        return True
    except Exception:
        return False


# ── midPoint: app-role matrix via role inducements (proper pattern) ──────────

def _mp_app_roles_from_inducements() -> tuple[dict, bool]:
    """Read app-role matrix from midPoint: RoleType.inducement → ServiceType.
    Returns ({app_id: [role_names]}, from_midpoint)."""
    now = time.time()
    if (_mp_inducement_cache["app_roles"] is not None
            and now - _mp_inducement_cache["fetched_at"] < MP_INDUCEMENT_CACHE_TTL):
        return _mp_inducement_cache["app_roles"], True
    try:
        # Build service OID → app_id map from cache
        _mp_service_oids_refresh()
        svc_oid_to_name = {v: k for k, v in _mp_cache["service_oids"].items()}

        r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/roles",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=8,
        )
        r.raise_for_status()
        raw = r.json().get("object", {}).get("object", [])
        if isinstance(raw, dict):
            raw = [raw]

        result = {}
        for role in raw:
            rname = role.get("name", "")
            if isinstance(rname, dict):
                rname = rname.get("orig", "")
            if not rname or rname not in ROLES:
                continue  # skip midPoint system roles
            inducements = role.get("inducement", [])
            if isinstance(inducements, dict):
                inducements = [inducements]
            for ind in (inducements or []):
                ref      = ind.get("targetRef", {})
                ref_type = ref.get("type", "")
                ref_oid  = ref.get("oid", "")
                if "ServiceType" in ref_type and ref_oid in svc_oid_to_name:
                    result.setdefault(svc_oid_to_name[ref_oid], []).append(rname)

        _mp_inducement_cache["app_roles"]  = result
        _mp_inducement_cache["fetched_at"] = now
        return result, True
    except Exception:
        if _mp_inducement_cache["app_roles"] is not None:
            return _mp_inducement_cache["app_roles"], True
        return {}, False


def _mp_set_app_roles(app_id: str, service_oid: str, selected_roles: list) -> bool:
    """Update midPoint role inducements so each role in selected_roles induces service_oid.
    Only modifies roles that actually changed. Returns True if all updates succeeded."""
    roles_map = _mp_roles_map()  # role_name → oid

    # Diff against current midPoint state (minimise API calls)
    current_map, _ = _mp_app_roles_from_inducements()
    current = set(current_map.get(app_id, []))
    target  = set(selected_roles)
    to_add    = target  - current
    to_remove = current - target
    changed   = to_add | to_remove

    if not changed:
        return True

    success = True
    for role_name in changed:
        role_oid = roles_map.get(role_name)
        if not role_oid:
            continue
        try:
            get_r = requests.get(
                f"{MIDPOINT_URL}/midpoint/ws/rest/roles/{role_oid}",
                auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
                headers={"Accept": "application/json"},
                timeout=5,
            )
            get_r.raise_for_status()
            role_obj = get_r.json().get("object", {})
            if not role_obj.get("oid"):
                app.logger.warning(f"_mp_set_app_roles: GET role {role_name} returned no oid")
                success = False
                continue

            inds = role_obj.get("inducement", [])
            if isinstance(inds, dict):
                inds = [inds]
            inds = list(inds or [])

            if role_name in to_add:
                inds.append({"targetRef": {"oid": service_oid, "type": "ServiceType"}})
            else:
                inds = [i for i in inds
                        if i.get("targetRef", {}).get("oid") != service_oid]

            # Send minimal PUT — avoid re-submitting system fields (operationExecution,
            # metadata, trigger, fetchResult) which can cause midPoint addObject errors.
            put_body = {"oid": role_oid, "name": role_name, "inducement": inds}
            put_r = requests.put(
                f"{MIDPOINT_URL}/midpoint/ws/rest/roles/{role_oid}",
                auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
                headers={"Content-Type": "application/json"},
                json={"role": put_body},
                timeout=10,
            )
            if not put_r.ok:
                app.logger.warning(
                    f"_mp_set_app_roles PUT {role_name}: {put_r.status_code} "
                    f"{put_r.text[:300].replace(chr(10), ' ')}"
                )
                success = False
            else:
                put_r.raise_for_status()
        except Exception as exc:
            app.logger.warning(f"_mp_set_app_roles {role_name}: exception {exc}")
            success = False

    _mp_invalidate_inducements()
    return success


# ── midPoint: user role assignments (authoritative for /users page) ───────────

_mp_user_cache: dict = {"roles": None, "user_oids": {}, "fetched_at": 0.0}


def _mp_invalidate_users():
    _mp_user_cache["roles"]     = None
    _mp_user_cache["user_oids"] = {}
    _mp_user_cache["fetched_at"] = 0.0


def _mp_roles_map() -> dict:
    """Fetch all midPoint RoleType objects. Returns {role_name: oid}."""
    try:
        r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/roles",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=5,
        )
        r.raise_for_status()
        raw = r.json().get("object", {}).get("object", [])
        if isinstance(raw, dict):
            raw = [raw]
        result = {}
        for role in raw:
            name = role.get("name", "")
            if isinstance(name, dict):
                name = name.get("orig", "")
            oid = role.get("oid", "")
            if name and oid:
                result[name] = oid
        return result
    except Exception:
        return {}


def _mp_user_roles():
    """Fetch user→[role_names] from midPoint UserType assignment refs.
    Returns ({username: [roles]}, {username: oid}, from_midpoint)."""
    now = time.time()
    if (_mp_user_cache["roles"] is not None
            and now - _mp_user_cache["fetched_at"] < MP_USER_CACHE_TTL):
        return _mp_user_cache["roles"], _mp_user_cache["user_oids"], True
    try:
        roles_by_name = _mp_roles_map()
        oid_to_name   = {v: k for k, v in roles_by_name.items()}
        r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/users",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=8,
        )
        r.raise_for_status()
        raw = r.json().get("object", {}).get("object", [])
        if isinstance(raw, dict):
            raw = [raw]
        user_roles = {}
        user_oids  = {}
        for user in raw:
            uname = user.get("name", "")
            if isinstance(uname, dict):
                uname = uname.get("orig", "")
            if not uname:
                continue
            oid = user.get("oid", "")
            assignments = user.get("assignment", [])
            if isinstance(assignments, dict):
                assignments = [assignments]
            roles = []
            for asgn in (assignments or []):
                ref      = asgn.get("targetRef", {})
                ref_type = ref.get("type", "")
                ref_oid  = ref.get("oid", "")
                if "RoleType" in ref_type and ref_oid:
                    role_name = oid_to_name.get(ref_oid)
                    if role_name:
                        roles.append(role_name)
            user_roles[uname] = roles
            if oid:
                user_oids[uname] = oid
        _mp_user_cache["roles"]     = user_roles
        _mp_user_cache["user_oids"] = user_oids
        _mp_user_cache["fetched_at"] = now
        return user_roles, user_oids, True
    except Exception:
        if _mp_user_cache["roles"] is not None:
            return _mp_user_cache["roles"], _mp_user_cache["user_oids"], True
        return None, {}, False


def _mp_save_user_roles(username: str, selected_roles: list) -> bool:
    """Write user role assignments back to midPoint (best-effort governance record).
    Preserves non-RoleType assignments (org memberships, etc.). Returns True on success."""
    _, user_oids, mp_ok = _mp_user_roles()
    if not mp_ok:
        return False
    user_oid = user_oids.get(username)
    if not user_oid:
        return False  # user not yet provisioned in midPoint
    roles_map = _mp_roles_map()  # name → oid
    try:
        # Fetch full user object to preserve non-role assignments
        get_r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/users/{user_oid}",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=5,
        )
        get_r.raise_for_status()
        user_obj = get_r.json().get("object", {})
        existing = user_obj.get("assignment", [])
        if isinstance(existing, dict):
            existing = [existing]
        # Keep non-RoleType assignments (org, service, etc.)
        kept = [a for a in (existing or [])
                if "RoleType" not in a.get("targetRef", {}).get("type", "")]
        new_role_asgns = [
            {"targetRef": {"oid": roles_map[r], "type": "RoleType"}}
            for r in selected_roles if r in roles_map
        ]
        user_obj["assignment"] = kept + new_role_asgns
        user_obj.pop("version", None)
        put_r = requests.put(
            f"{MIDPOINT_URL}/midpoint/ws/rest/users/{user_oid}",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Content-Type": "application/json"},
            json={"user": user_obj},
            timeout=10,
        )
        put_r.raise_for_status()
        _mp_invalidate_users()
        return True
    except Exception:
        return False


def _mp_ensure_roles() -> dict:
    """Idempotently create all custom roles in midPoint. Returns {role: status}."""
    results = {}
    for role_name in ROLES:
        try:
            r = requests.post(
                f"{MIDPOINT_URL}/midpoint/ws/rest/roles",
                auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                json={"role": {
                    "name":        role_name,
                    "displayName": role_name.replace("_", " ").title(),
                    "description": f"Data Masking role: {role_name}",
                }},
                timeout=10,
            )
            if r.status_code in (200, 201):
                results[role_name] = "created"
            elif r.status_code == 409:
                results[role_name] = "exists"
            else:
                body = r.text[:200].replace("\n", " ")
                results[role_name] = f"error:{r.status_code}:{body}"
        except Exception as exc:
            results[role_name] = f"error:exc:{exc}"
    # invalidate caches so _mp_roles_map picks up new roles
    _mp_invalidate_users()
    return results


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(DATABASE_URL)


def qrows(conn, sql, params=()):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def qone(conn, sql, params=()):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def scalar(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return row[0] if row else None


def execute(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)


def executemany(conn, sql, params_list):
    with conn.cursor() as cur:
        cur.executemany(sql, params_list)


# ── Schema init ───────────────────────────────────────────────────────────────

def init_db():
    conn = get_db()
    stmts = [
        """CREATE TABLE IF NOT EXISTS vip_customers (
            customer_id TEXT PRIMARY KEY,
            added_by    TEXT DEFAULT 'system',
            added_at    TEXT NOT NULL,
            notes       TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS customer_tiers (
            customer_id TEXT PRIMARY KEY,
            tier        TEXT NOT NULL DEFAULT 'vip',
            added_by    TEXT DEFAULT 'system',
            added_at    TEXT NOT NULL,
            notes       TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS role_field_masks (
            role  TEXT NOT NULL,
            field TEXT NOT NULL,
            PRIMARY KEY (role, field)
        )""",
        """CREATE TABLE IF NOT EXISTS sync_log (
            id        SERIAL PRIMARY KEY,
            synced_at TEXT NOT NULL,
            status    TEXT NOT NULL,
            message   TEXT
        )""",
        """CREATE TABLE IF NOT EXISTS backends (
            backend_id   TEXT PRIMARY KEY,
            backend_name TEXT NOT NULL,
            base_url     TEXT DEFAULT '',
            description  TEXT DEFAULT '',
            created_at   TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS field_mappings (
            id              SERIAL PRIMARY KEY,
            backend_id      TEXT NOT NULL REFERENCES backends(backend_id) ON DELETE CASCADE,
            backend_field   TEXT NOT NULL,
            canonical_field TEXT NOT NULL,
            classification  TEXT NOT NULL DEFAULT 'L1',
            UNIQUE(backend_id, backend_field)
        )""",
        """CREATE TABLE IF NOT EXISTS apps (
            app_id       TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            upstream_url TEXT DEFAULT '',
            description  TEXT DEFAULT '',
            mp_oid       TEXT DEFAULT '',
            added_by     TEXT DEFAULT 'system',
            added_at     TEXT NOT NULL
        )""",
        "ALTER TABLE apps ADD COLUMN IF NOT EXISTS mp_oid TEXT DEFAULT ''",
        """CREATE TABLE IF NOT EXISTS app_roles (
            app_id TEXT NOT NULL REFERENCES apps(app_id) ON DELETE CASCADE,
            role   TEXT NOT NULL,
            PRIMARY KEY (app_id, role)
        )""",
        """CREATE TABLE IF NOT EXISTS purpose_policies (
            id         SERIAL PRIMARY KEY,
            role       TEXT NOT NULL,
            purpose    TEXT NOT NULL,
            field      TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT '',
            UNIQUE(role, purpose, field)
        )""",
        """CREATE TABLE IF NOT EXISTS masking_rules (
            id                         SERIAL PRIMARY KEY,
            name                       TEXT    NOT NULL,
            priority                   INT     NOT NULL DEFAULT 100,
            condition_roles            TEXT[]  NOT NULL DEFAULT '{}',
            condition_tiers            TEXT[]  NOT NULL DEFAULT '{}',
            condition_purposes         TEXT[]  NOT NULL DEFAULT '{}',
            condition_channels         TEXT[]  NOT NULL DEFAULT '{}',
            condition_in_working_hours BOOLEAN,
            action                     TEXT    NOT NULL CHECK (action IN ('mask','unmask')),
            fields                     TEXT[]  NOT NULL DEFAULT '{}',
            enabled                    BOOLEAN NOT NULL DEFAULT true,
            created_at                 TEXT    NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS unmask_sessions (
            id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      TEXT        NOT NULL DEFAULT '',
            username     TEXT        NOT NULL,
            customer_id  TEXT        NOT NULL,
            fields       TEXT[]      NOT NULL DEFAULT '{}',
            reason_code  TEXT        NOT NULL,
            ticket_ref   TEXT        NOT NULL DEFAULT '',
            notes        TEXT        NOT NULL DEFAULT '',
            status       TEXT        NOT NULL DEFAULT 'pending',
            requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at  TIMESTAMPTZ,
            reviewed_by  TEXT,
            expires_at   TIMESTAMPTZ,
            first_used_at TIMESTAMPTZ,
            used_at      TIMESTAMPTZ
        )""",
    ]
    for stmt in stmts:
        execute(conn, stmt)

    now = datetime.utcnow().isoformat()
    # Migrate old vip_customers rows into customer_tiers as tier='vip'
    execute(conn,
        """INSERT INTO customer_tiers (customer_id, tier, added_by, added_at, notes)
           SELECT customer_id, 'vip', added_by, added_at, notes
           FROM vip_customers
           ON CONFLICT (customer_id) DO NOTHING"""
    )
    if not qone(conn, "SELECT 1 FROM customer_tiers LIMIT 1"):
        executemany(conn,
            "INSERT INTO customer_tiers (customer_id, tier, added_by, added_at, notes) "
            "VALUES (%s, %s, 'system', %s, %s)",
            [(cid, tier, now, note) for cid, tier, note in _DEFAULT_TIERS],
        )
    if not qone(conn, "SELECT 1 FROM role_field_masks LIMIT 1"):
        executemany(conn,
            "INSERT INTO role_field_masks (role, field) VALUES (%s, %s)",
            _DEFAULT_MASKS,
        )
    if not qone(conn, "SELECT 1 FROM backends LIMIT 1"):
        executemany(conn,
            "INSERT INTO backends (backend_id, backend_name, base_url, description, created_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            [(bid, name, url, desc, now) for bid, name, url, desc in _DEFAULT_BACKENDS],
        )
    if not qone(conn, "SELECT 1 FROM field_mappings LIMIT 1"):
        executemany(conn,
            "INSERT INTO field_mappings (backend_id, backend_field, canonical_field, classification) "
            "VALUES (%s, %s, %s, %s)",
            _DEFAULT_FIELD_MAPPINGS,
        )
    if not qone(conn, "SELECT 1 FROM apps LIMIT 1"):
        executemany(conn,
            "INSERT INTO apps (app_id, name, upstream_url, description, added_by, added_at) "
            "VALUES (%s, %s, %s, %s, 'system', %s)",
            [(aid, name, url, desc, now) for aid, name, url, desc in _DEFAULT_APPS],
        )
        executemany(conn,
            "INSERT INTO app_roles (app_id, role) VALUES (%s, %s)",
            _DEFAULT_APP_ROLES,
        )
    if not qone(conn, "SELECT 1 FROM purpose_policies LIMIT 1"):
        _default_purpose_policies = [
            # care_l1: fraud investigation unlocks msisdn + email
            ("care_l1",    "fraud_investigation", "msisdn"),
            ("care_l1",    "fraud_investigation", "email"),
            # care_l2: fraud investigation unlocks national_id
            ("care_l2",    "fraud_investigation", "national_id"),
            ("care_l2",    "fraud_investigation", "address"),
            # care_l1: compliance audit unlocks email + address
            ("care_l1",    "compliance_audit",    "email"),
            ("care_l1",    "compliance_audit",    "address"),
            # billing_agent: billing dispute unlocks national_id
            ("billing_agent", "billing_dispute",  "national_id"),
            # audit_viewer: compliance audit unlocks name + email
            ("audit_viewer",  "compliance_audit", "name"),
            ("audit_viewer",  "compliance_audit", "email"),
            # audit_viewer: regulator_request unlocks name + msisdn + email
            ("audit_viewer",  "regulator_request", "name"),
            ("audit_viewer",  "regulator_request", "msisdn"),
            ("audit_viewer",  "regulator_request", "email"),
        ]
        executemany(conn,
            "INSERT INTO purpose_policies (role, purpose, field, created_at) VALUES (%s, %s, %s, %s)",
            [(r, p, f, now) for r, p, f in _default_purpose_policies],
        )
    if not qone(conn, "SELECT 1 FROM masking_rules LIMIT 1"):
        for priority, name, roles, tiers, purposes, channels, wh, action, fields in _DEFAULT_RULES:
            execute(conn,
                """INSERT INTO masking_rules
                   (priority, name, condition_roles, condition_tiers, condition_purposes,
                    condition_channels, condition_in_working_hours, action, fields, enabled, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, true, %s)""",
                (priority, name, roles, tiers, purposes, channels, wh, action, fields, now))
    conn.commit()
    conn.close()


# ── Config assembly ───────────────────────────────────────────────────────────

def get_config():
    conn = get_db()
    tier_rows     = qrows(conn, "SELECT customer_id, tier FROM customer_tiers")
    mask_rows     = qrows(conn, "SELECT role, field FROM role_field_masks")
    mapping_rows  = qrows(conn,
        "SELECT backend_id, backend_field, canonical_field, classification "
        "FROM field_mappings ORDER BY backend_id, backend_field"
    )
    purpose_rows  = qrows(conn,
        "SELECT role, purpose, field FROM purpose_policies ORDER BY role, purpose, field"
    )
    rule_rows     = qrows(conn,
        "SELECT id, name, priority, condition_roles, condition_tiers, condition_purposes, "
        "condition_channels, condition_in_working_hours, action, fields, enabled "
        "FROM masking_rules ORDER BY priority, id"
    )
    app_role_rows = qrows(conn,
        "SELECT app_id, role FROM app_roles ORDER BY app_id, role"
    )
    conn.close()

    customer_tiers = {row["customer_id"]: row["tier"] for row in tier_rows}

    role_masked_fields = {role: [] for role in ROLES}
    for row in mask_rows:
        if row["role"] in role_masked_fields:
            role_masked_fields[row["role"]].append(row["field"])

    backends = {}
    for row in mapping_rows:
        bid = row["backend_id"]
        if bid not in backends:
            backends[bid] = {}
        backends[bid][row["backend_field"]] = {
            "canonical":      row["canonical_field"],
            "classification": row["classification"],
        }

    # App roles: midPoint inducements authoritative; DB rows are fallback when MP down
    mp_app_roles, mp_inducement_ok = _mp_app_roles_from_inducements()
    if mp_inducement_ok:
        app_roles = mp_app_roles
    else:
        app_roles = {}
        for row in app_role_rows:
            app_roles.setdefault(row["app_id"], []).append(row["role"])

    purpose_overrides = {}
    for row in purpose_rows:
        purpose_overrides.setdefault(row["role"], {}).setdefault(row["purpose"], []).append(row["field"])

    masking_rules = []
    for row in rule_rows:
        masking_rules.append({
            "id":                         row["id"],
            "name":                       row["name"],
            "priority":                   row["priority"],
            "condition_roles":            list(row["condition_roles"] or []),
            "condition_tiers":            list(row["condition_tiers"] or []),
            "condition_purposes":         list(row["condition_purposes"] or []),
            "condition_channels":         list(row["condition_channels"] or []),
            "condition_in_working_hours": row["condition_in_working_hours"],
            "action":                     row["action"],
            "fields":                     list(row["fields"] or []),
            "enabled":                    row["enabled"],
        })

    return {
        "customer_tiers":     customer_tiers,
        "role_masked_fields": role_masked_fields,
        "backends":           backends,
        "app_roles":          app_roles,
        "purpose_overrides":  purpose_overrides,
        "masking_rules":      masking_rules,
    }


# ── OPA sync ──────────────────────────────────────────────────────────────────

def sync_to_opa(retries=3):
    status  = "ok"
    message = "bundle mode — OPA polls /bundle/masking_config.tar.gz automatically (≤60s)"
    conn = get_db()
    execute(conn,
        "INSERT INTO sync_log (synced_at, status, message) VALUES (%s, %s, %s)",
        (datetime.utcnow().isoformat(), status, message),
    )
    conn.commit()
    conn.close()
    return True, message


# ── OPA bundle endpoint ───────────────────────────────────────────────────────

def build_bundle():
    config         = get_config()
    data_bytes     = json.dumps(config).encode("utf-8")
    manifest_bytes = json.dumps({"revision": "", "roots": ["masking_config"]}).encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        minfo      = tarfile.TarInfo(name=".manifest")
        minfo.size = len(manifest_bytes)
        tar.addfile(minfo, io.BytesIO(manifest_bytes))
        info      = tarfile.TarInfo(name="masking_config/data.json")
        info.size = len(data_bytes)
        tar.addfile(info, io.BytesIO(data_bytes))
    buf.seek(0)
    return buf.read()


@app.get("/bundle/masking_config.tar.gz")
def bundle_endpoint():
    data = build_bundle()
    resp = make_response(data)
    resp.headers["Content-Type"]        = "application/gzip"
    resp.headers["Content-Disposition"] = "attachment; filename=masking_config.tar.gz"
    return resp


# ── Auth ──────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USER
                and request.form.get("password") == ADMIN_PASS):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/")
@login_required
def dashboard():
    config = get_config()
    conn   = get_db()
    recent_syncs  = qrows(conn, "SELECT * FROM sync_log ORDER BY id DESC LIMIT 5")
    backend_count = scalar(conn, "SELECT COUNT(*) FROM backends")
    mapping_count = scalar(conn, "SELECT COUNT(*) FROM field_mappings")
    conn.close()
    total_mask_count = sum(len(v) for v in config["role_masked_fields"].values())
    return render_template("dashboard.html",
                           config=config, recent_syncs=recent_syncs,
                           fields=FIELDS, roles=ROLES,
                           total_mask_count=total_mask_count,
                           backend_count=backend_count,
                           mapping_count=mapping_count)


@app.get("/health")
def health():
    conn = None
    try:
        conn = get_db()
        scalar(conn, "SELECT 1")
        return jsonify({"status": "ok"})
    except Exception as exc:
        return jsonify({"status": "error", "detail": str(exc)}), 503
    finally:
        if conn:
            conn.close()


# ── Customer tier management ──────────────────────────────────────────────────

@app.get("/vip")
@login_required
def vip_list():
    return redirect(url_for("tier_list"))


@app.get("/tiers")
@login_required
def tier_list():
    conn      = get_db()
    customers = qrows(conn, "SELECT * FROM customer_tiers ORDER BY tier, added_at DESC")
    conn.close()
    return render_template("tiers.html", customers=customers, valid_tiers=VALID_TIERS)


@app.post("/tiers/add")
@login_required
def tier_add():
    cid   = (request.form.get("customer_id") or "").strip().upper()
    tier  = (request.form.get("tier") or "vip").strip().lower()
    notes = (request.form.get("notes") or "").strip()
    if not cid:
        flash("Customer ID is required", "danger")
        return redirect(url_for("tier_list"))
    if tier not in VALID_TIERS:
        flash(f"Invalid tier '{tier}'", "danger")
        return redirect(url_for("tier_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO customer_tiers (customer_id, tier, added_by, added_at, notes) "
            "VALUES (%s, %s, %s, %s, %s)",
            (cid, tier, ADMIN_USER, datetime.utcnow().isoformat(), notes),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(
            f"Added {cid} as {tier.upper()} tier " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
            "success" if ok else "warning",
        )
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"'{cid}' already has a tier assigned — remove it first to reassign", "warning")
    finally:
        conn.close()
    return redirect(url_for("tier_list"))


@app.post("/tiers/remove/<customer_id>")
@login_required
def tier_remove(customer_id):
    conn = get_db()
    execute(conn, "DELETE FROM customer_tiers WHERE customer_id = %s", (customer_id,))
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash(
        f"Removed {customer_id} from tier management (reverts to standard) "
        + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
        "success" if ok else "warning",
    )
    return redirect(url_for("tier_list"))


# ── Masking rules (role × field matrix) ──────────────────────────────────────

@app.get("/roles")
@login_required
def roles_view():
    conn      = get_db()
    mask_rows = qrows(conn, "SELECT role, field FROM role_field_masks")
    conn.close()
    masked = {role: {f: False for f, _ in FIELDS} for role in ROLES}
    for row in mask_rows:
        if row["role"] in masked and row["field"] in masked[row["role"]]:
            masked[row["role"]][row["field"]] = True
    return render_template("roles.html", roles=ROLES, fields=FIELDS, masked=masked)


@app.post("/roles/save")
@login_required
def roles_save():
    conn    = get_db()
    inserts = [
        (role, field)
        for role in ROLES
        for field, _ in FIELDS
        if request.form.get(f"{role}__{field}")
    ]
    execute(conn, "DELETE FROM role_field_masks")
    if inserts:
        executemany(conn,
            "INSERT INTO role_field_masks (role, field) VALUES (%s, %s)", inserts
        )
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash(
        "Masking rules saved " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
        "success" if ok else "warning",
    )
    return redirect(url_for("roles_view"))


# ── Backend registry (field alias mapping) ───────────────────────────────────

@app.get("/backends")
@login_required
def backends_list():
    conn     = get_db()
    backends = qrows(conn, "SELECT * FROM backends ORDER BY backend_id")
    mappings = qrows(conn, "SELECT * FROM field_mappings ORDER BY backend_id, backend_field")
    conn.close()
    mapped = {}
    for m in mappings:
        mapped.setdefault(m["backend_id"], []).append(m)
    return render_template("backends.html",
                           backends=backends, mapped=mapped,
                           fields=FIELDS,
                           canonical_fields=[f for f, _ in FIELDS])


@app.post("/backends/add")
@login_required
def backend_add():
    bid  = (request.form.get("backend_id")   or "").strip().lower()
    name = (request.form.get("backend_name") or "").strip()
    url  = (request.form.get("base_url")     or "").strip()
    desc = (request.form.get("description")  or "").strip()
    if not bid or not name:
        flash("Backend ID and name are required", "danger")
        return redirect(url_for("backends_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO backends (backend_id, backend_name, base_url, description, created_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (bid, name, url, desc, datetime.utcnow().isoformat()),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(f"Backend '{bid}' added " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
              "success" if ok else "warning")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"Backend ID '{bid}' already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("backends_list"))


@app.post("/backends/<backend_id>/delete")
@login_required
def backend_delete(backend_id):
    conn = get_db()
    execute(conn, "DELETE FROM backends WHERE backend_id = %s", (backend_id,))
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash(f"Backend '{backend_id}' deleted " + ("– synced to OPA ✓" if ok else f"– sync failed: {msg}"),
          "success" if ok else "warning")
    return redirect(url_for("backends_list"))


@app.post("/backends/<backend_id>/fields/add")
@login_required
def field_mapping_add(backend_id):
    bfield = (request.form.get("backend_field")   or "").strip()
    canon  = (request.form.get("canonical_field") or "").strip()
    cls    = (request.form.get("classification")  or "L1").strip()
    if not bfield or not canon:
        flash("Backend field and canonical field are required", "danger")
        return redirect(url_for("backends_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO field_mappings (backend_id, backend_field, canonical_field, classification) "
            "VALUES (%s, %s, %s, %s)",
            (backend_id, bfield, canon, cls),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(f"Mapping {bfield}→{canon} added " + ("– synced ✓" if ok else f"– sync failed: {msg}"),
              "success" if ok else "warning")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"Field '{bfield}' already mapped for backend '{backend_id}'", "warning")
    finally:
        conn.close()
    return redirect(url_for("backends_list"))


@app.post("/backends/<backend_id>/fields/<int:field_id>/delete")
@login_required
def field_mapping_delete(backend_id, field_id):
    conn = get_db()
    execute(conn, "DELETE FROM field_mappings WHERE id = %s AND backend_id = %s",
            (field_id, backend_id))
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash("Mapping removed " + ("– synced ✓" if ok else f"– sync failed: {msg}"),
          "success" if ok else "warning")
    return redirect(url_for("backends_list"))


# ── Purpose-driven masking policies ──────────────────────────────────────────

@app.get("/purpose-policies")
@login_required
def purpose_policies_list():
    conn = get_db()
    rows = qrows(conn, "SELECT * FROM purpose_policies ORDER BY role, purpose, field")
    conn.close()
    policy_map = {}
    for row in rows:
        policy_map.setdefault(row["role"], {}).setdefault(row["purpose"], []).append(row["field"])
    return render_template("purpose_policies.html",
                           policy_map=policy_map, roles=ROLES,
                           purposes=PURPOSES, fields=[f for f, _ in FIELDS])


@app.post("/purpose-policies/add")
@login_required
def purpose_policy_add():
    role    = request.form.get("role", "").strip()
    purpose = request.form.get("purpose", "").strip()
    field   = request.form.get("field", "").strip()
    if not role or not purpose or not field:
        flash("Role, purpose, and field are all required", "danger")
        return redirect(url_for("purpose_policies_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO purpose_policies (role, purpose, field, created_at) VALUES (%s,%s,%s,%s)",
            (role, purpose, field, datetime.utcnow().isoformat()))
        conn.commit()
        flash(f"Purpose policy added: {role} + {purpose} → {field} unmasked", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Already exists or error: {e}", "warning")
    finally:
        conn.close()
    return redirect(url_for("purpose_policies_list"))


@app.post("/purpose-policies/delete")
@login_required
def purpose_policy_delete():
    role    = request.form.get("role")
    purpose = request.form.get("purpose")
    field   = request.form.get("field")
    conn = get_db()
    execute(conn, "DELETE FROM purpose_policies WHERE role=%s AND purpose=%s AND field=%s",
            (role, purpose, field))
    conn.commit()
    conn.close()
    flash(f"Removed: {role} + {purpose} → {field}", "success")
    return redirect(url_for("purpose_policies_list"))


# ── Masking simulation ────────────────────────────────────────────────────────

@app.route("/simulate", methods=["GET", "POST"])
@login_required
def simulate():
    result = None
    error  = None
    form   = {}
    if request.method == "POST":
        form = request.form
        role         = form.get("role", "agent")
        customer_id  = form.get("customer_id", "C002")
        purpose      = form.get("purpose", "")
        channel      = form.get("channel", "web")
        initiated_by = form.get("initiated_by", "customer")
        session_type = form.get("session_type", "normal")
        in_wh        = form.get("in_working_hours", "true") == "true"
        backend      = form.get("backend", "crm")
        app_id       = form.get("app_id", "")
        opa_input = {
            "input": {
                "role":        role,
                "username":    "simulate",
                "path":        f"/api/customer/{customer_id}",
                "method":      "GET",
                "customer_id": customer_id,
                "backend":     backend,
                "app_id":      app_id,
                "ctx": {
                    "purpose":          purpose,
                    "channel":          channel,
                    "initiated_by":     initiated_by,
                    "session_type":     session_type,
                    "in_working_hours": in_wh,
                },
            }
        }
        try:
            resp = requests.post(
                f"{OPA_URL}/v1/data/data_masking/decision",
                json=opa_input, timeout=5,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
        except Exception as exc:
            error = str(exc)
    all_fields = [f for f, _ in FIELDS]
    return render_template("simulate.html",
                           roles=ROLES, purposes=PURPOSES,
                           all_fields=all_fields, result=result,
                           error=error, form=form)


# ── Application registry ─────────────────────────────────────────────────────

@app.get("/apps")
@login_required
def apps_list():
    conn          = get_db()
    apps = qrows(conn, "SELECT * FROM apps ORDER BY app_id")
    conn.close()
    mp_app_roles, mp_ok = _mp_app_roles_from_inducements()
    if mp_ok:
        app_role_map = mp_app_roles
        mp_source    = True
    else:
        conn2 = get_db()
        rows  = qrows(conn2, "SELECT app_id, role FROM app_roles ORDER BY app_id, role")
        conn2.close()
        app_role_map = {}
        for r in rows:
            app_role_map.setdefault(r["app_id"], []).append(r["role"])
        mp_source = False
    return render_template("apps.html", apps=apps, app_role_map=app_role_map,
                           roles=ROLES, mp_source=mp_source)


@app.post("/apps/add")
@login_required
def apps_add():
    app_id = (request.form.get("app_id")       or "").strip().lower()
    name   = (request.form.get("name")         or "").strip()
    url    = (request.form.get("upstream_url") or "").strip()
    desc   = (request.form.get("description")  or "").strip()
    if not app_id or not name:
        flash("App ID and name are required", "danger")
        return redirect(url_for("apps_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO apps (app_id, name, upstream_url, description, mp_oid, added_by, added_at) "
            "VALUES (%s, %s, %s, %s, '', 'admin', %s)",
            (app_id, name, url, desc, datetime.utcnow().isoformat()))
        conn.commit()
        # Create Service in midPoint for visibility/audit (best effort)
        mp_oid = _mp_create_service(app_id, name, desc)
        if mp_oid:
            execute(conn, "UPDATE apps SET mp_oid = %s WHERE app_id = %s", (mp_oid, app_id))
            conn.commit()
            flash(f"App '{app_id}' registered and visible in midPoint — set allowed roles below.", "success")
        else:
            flash(f"App '{app_id}' registered — midPoint unreachable, Service not created.", "warning")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"App ID '{app_id}' already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("apps_list"))


@app.post("/apps/remove/<app_id>")
@login_required
def apps_remove(app_id):
    # Delete from midPoint first (best effort — before DB row gone)
    mp_ok = _mp_delete_service(app_id)
    conn  = get_db()
    execute(conn, "DELETE FROM apps WHERE app_id = %s", (app_id,))
    conn.commit()
    conn.close()
    suffix = "— removed from midPoint ✓" if mp_ok else "— midPoint Service may still exist, delete manually."
    flash(f"App '{app_id}' removed {suffix}", "success" if mp_ok else "warning")
    return redirect(url_for("apps_list"))


@app.post("/apps/<app_id>/roles/save")
@login_required
def apps_roles_save(app_id):
    selected = [r for r in ROLES if request.form.get(f"role__{r}")]
    # Always write to DB (source of truth for fallback)
    conn = get_db()
    execute(conn, "DELETE FROM app_roles WHERE app_id = %s", (app_id,))
    if selected:
        executemany(conn, "INSERT INTO app_roles (app_id, role) VALUES (%s, %s)",
                    [(app_id, r) for r in selected])
    conn.commit()
    conn.close()
    # Write inducements to midPoint (authoritative)
    service_oid = _mp_service_oid(app_id)
    if service_oid:
        mp_ok = _mp_set_app_roles(app_id, service_oid, selected)
        suffix = "midPoint inducements updated, " if mp_ok else "midPoint sync partial — "
    else:
        suffix = "app not in midPoint (run Init midPoint Services) — "
    sync_to_opa()
    flash(f"Roles saved for '{app_id}' — {suffix}OPA reloads within 60s.", "success" if service_oid else "warning")
    return redirect(url_for("apps_list"))


# ── Dynamic rule engine ──────────────────────────────────────────────────────

@app.get("/rules")
@login_required
def rules_list():
    conn = get_db()
    rules = qrows(conn, "SELECT * FROM masking_rules ORDER BY priority, id")
    conn.close()
    return render_template("rules.html", rules=rules,
                           all_roles=ROLES, all_purposes=PURPOSES,
                           all_fields=FIELDS, tiers=TIERS, channels=CHANNELS)


@app.post("/rules/add")
@login_required
def rules_add():
    name      = (request.form.get("name") or "").strip()
    priority  = int(request.form.get("priority") or 100)
    action    = (request.form.get("action") or "unmask").strip()
    roles     = request.form.getlist("condition_roles")
    tiers     = request.form.getlist("condition_tiers")
    purposes  = request.form.getlist("condition_purposes")
    channels  = request.form.getlist("condition_channels")
    wh_val    = request.form.get("condition_in_working_hours", "any")
    wh        = None if wh_val == "any" else (wh_val == "true")
    fields    = request.form.getlist("fields")

    if not name or not fields or action not in ("mask", "unmask"):
        flash("Name, action, and at least one field are required", "danger")
        return redirect(url_for("rules_list"))

    conn = get_db()
    try:
        execute(conn,
            """INSERT INTO masking_rules
               (name, priority, condition_roles, condition_tiers, condition_purposes,
                condition_channels, condition_in_working_hours, action, fields, enabled, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, true, %s)""",
            (name, priority, roles, tiers, purposes, channels, wh, action, fields,
             datetime.utcnow().isoformat()))
        conn.commit()
        flash(f"Rule '{name}' added — OPA will reload within 60s", "success")
    except Exception as exc:
        conn.rollback()
        flash(f"Error: {exc}", "danger")
    finally:
        conn.close()
    return redirect(url_for("rules_list"))


@app.post("/rules/<int:rule_id>/toggle")
@login_required
def rules_toggle(rule_id):
    conn = get_db()
    execute(conn, "UPDATE masking_rules SET enabled = NOT enabled WHERE id = %s", (rule_id,))
    conn.commit()
    conn.close()
    flash("Rule toggled — OPA will reload within 60s", "success")
    return redirect(url_for("rules_list"))


@app.post("/rules/<int:rule_id>/delete")
@login_required
def rules_delete(rule_id):
    conn = get_db()
    row = qone(conn, "SELECT name FROM masking_rules WHERE id = %s", (rule_id,))
    execute(conn, "DELETE FROM masking_rules WHERE id = %s", (rule_id,))
    conn.commit()
    conn.close()
    flash(f"Rule '{row['name'] if row else rule_id}' deleted", "success")
    return redirect(url_for("rules_list"))


# ── Manual OPA sync ───────────────────────────────────────────────────────────

@app.post("/sync")
@login_required
def manual_sync():
    ok, msg = sync_to_opa()
    flash(f"OPA re-polls bundle within 60s. {msg}", "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.get("/api/config")
@login_required
def api_config():
    return jsonify(get_config())


# ── Keycloak Admin API helpers ────────────────────────────────────────────────

def _kc_token():
    r = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
        data={"client_id": "admin-cli", "grant_type": "password",
              "username": KEYCLOAK_ADMIN_USER, "password": KEYCLOAK_ADMIN_PASS},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _kc_users_with_roles():
    """Fetch users from Keycloak; overlay role state from midPoint (authoritative).
    Falls back to Keycloak role-mappings when midPoint is unavailable.
    Returns (users_list, mp_available)."""
    token   = _kc_token()
    headers = {"Authorization": f"Bearer {token}"}
    users   = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users?max=200",
        headers=headers, timeout=10,
    )
    users.raise_for_status()
    result = users.json()

    # Try midPoint as authoritative role source
    mp_roles, _, mp_ok = _mp_user_roles()

    for u in result:
        uname = u.get("username", "")
        if mp_ok and mp_roles is not None and uname in mp_roles:
            u["app_roles"]   = mp_roles[uname]
            u["role_source"] = "midpoint"
        else:
            # Fall back to Keycloak role-mappings API
            kc_roles = requests.get(
                f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
                f"/users/{u['id']}/role-mappings/realm",
                headers=headers, timeout=10,
            ).json()
            u["app_roles"]   = [r["name"] for r in kc_roles
                                if not r["name"].startswith("default-roles")]
            u["role_source"] = "keycloak"
    return result, (mp_ok and mp_roles is not None)


def _kc_role_obj(token, role_name):
    r = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{role_name}",
        headers={"Authorization": f"Bearer {token}"}, timeout=10,
    )
    r.raise_for_status()
    return r.json()


# ── User lifecycle routes ─────────────────────────────────────────────────────

@app.get("/users")
@login_required
def users_list():
    try:
        users, mp_available = _kc_users_with_roles()
        error = None
    except Exception as exc:
        users, mp_available, error = [], False, str(exc)
    return render_template("users.html", users=users, roles=ROLES,
                           error=error, mp_available=mp_available)


@app.post("/users/add")
@login_required
def users_add():
    username   = (request.form.get("username")   or "").strip()
    email      = (request.form.get("email")      or "").strip()
    first_name = (request.form.get("first_name") or "").strip()
    last_name  = (request.form.get("last_name")  or "").strip()
    password   = (request.form.get("password")   or "").strip()
    role       = (request.form.get("role")       or "").strip()
    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for("users_list"))
    try:
        token   = _kc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {"username": username, "enabled": True,
                   "credentials": [{"type": "password", "value": password, "temporary": True}]}
        if email:      payload["email"]     = email
        if first_name: payload["firstName"] = first_name
        if last_name:  payload["lastName"]  = last_name
        r = requests.post(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
            headers=headers, json=payload, timeout=10,
        )
        r.raise_for_status()
        user_id = r.headers.get("Location", "").rstrip("/").split("/")[-1]
        if role and user_id:
            rd = _kc_role_obj(token, role)
            requests.post(
                f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
                f"/users/{user_id}/role-mappings/realm",
                headers=headers, json=[{"id": rd["id"], "name": role}], timeout=10,
            )
        flash(f"User '{username}' created" + (f" with role '{role}'" if role else ""), "success")
    except Exception as exc:
        flash(f"Error: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/roles/save")
@login_required
def users_roles_save(user_id):
    selected = [r for r in ROLES if request.form.get(f"role__{r}")]
    username = request.form.get("username", user_id)
    try:
        token   = _kc_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        existing = requests.get(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
            f"/users/{user_id}/role-mappings/realm",
            headers=headers, timeout=10,
        ).json()
        non_default = [r for r in existing if not r["name"].startswith("default-roles")]
        if non_default:
            requests.delete(
                f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
                f"/users/{user_id}/role-mappings/realm",
                headers=headers, json=non_default, timeout=10,
            )
        if selected:
            role_objs = [_kc_role_obj(token, rname) for rname in selected]
            role_objs = [{"id": rd["id"], "name": rd["name"]} for rd in role_objs]
            requests.post(
                f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
                f"/users/{user_id}/role-mappings/realm",
                headers=headers, json=role_objs, timeout=10,
            )
        # Best-effort: sync role state to midPoint governance record
        mp_synced = _mp_save_user_roles(username, selected)
        msg = f"Roles saved for '{username}'"
        if mp_synced:
            msg += " (synced to midPoint)"
        else:
            msg += " (midPoint sync skipped — user not in midPoint or MP unavailable)"
        flash(msg, "success")
    except Exception as exc:
        flash(f"Error: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/offboard")
@login_required
def users_offboard(user_id):
    username = request.form.get("username", user_id)
    try:
        token = _kc_token()
        requests.put(
            f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"enabled": False}, timeout=10,
        ).raise_for_status()
        flash(f"'{username}' offboarded — account disabled, all sessions revoked", "success")
    except Exception as exc:
        flash(f"Error: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/midpoint/init-services")
@login_required
def midpoint_init_services():
    """Seed all apps into midPoint: create ServiceType + set role inducements from DB."""
    conn = get_db()
    apps      = qrows(conn, "SELECT app_id, name, description FROM apps ORDER BY app_id")
    role_rows = qrows(conn, "SELECT app_id, role FROM app_roles ORDER BY app_id")
    conn.close()
    db_role_map: dict = {}
    for r in role_rows:
        db_role_map.setdefault(r["app_id"], []).append(r["role"])

    created, updated, errors = 0, 0, []
    for app in apps:
        app_id = app["app_id"]
        existing_oid = _mp_service_oid(app_id)
        if existing_oid:
            ok = _mp_update_service_meta(app_id)
            if ok:
                updated += 1
            else:
                errors.append(f"{app_id}:meta_update_failed")
            svc_oid = existing_oid
        else:
            svc_oid = _mp_create_service(app_id, app["name"] or app_id,
                                         app["description"] or "")
            if svc_oid:
                conn3 = get_db()
                with conn3.cursor() as cur:
                    cur.execute("UPDATE apps SET mp_oid = %s WHERE app_id = %s",
                                (svc_oid, app_id))
                conn3.commit()
                conn3.close()
                created += 1
            else:
                errors.append(f"{app_id}:create_failed")
                continue
        # Seed inducements from DB app_roles
        roles = db_role_map.get(app_id, [])
        if not _mp_set_app_roles(app_id, svc_oid, roles):
            errors.append(f"{app_id}:inducement_partial")
    msg = f"midPoint services: {created} created, {updated} updated"
    if errors:
        flash(msg + f" — errors: {errors}", "warning")
    else:
        flash(msg, "success")
    return redirect(url_for("apps_list"))


@app.post("/midpoint/init-roles")
@login_required
def midpoint_init_roles():
    results = _mp_ensure_roles()
    created = sum(1 for v in results.values() if v == "created")
    existed = sum(1 for v in results.values() if v == "exists")
    errors  = {k: v for k, v in results.items() if v.startswith("error")}
    msg = f"midPoint roles: {created} created, {existed} already existed"
    if errors:
        # Show first error value so root cause is visible
        first_err = next(iter(errors.values()))
        flash(msg + f" — {len(errors)} errors (first: {first_err})", "warning")
    else:
        flash(msg, "success")
    return redirect(url_for("users_list"))


@app.get("/midpoint/status")
def midpoint_status():
    """Diagnostic: test midPoint connectivity. Accepts browser session or X-Api-Key header."""
    api_key = request.headers.get("X-Api-Key", "")
    if api_key != GOVERNANCE_API_KEY and not session.get("admin_logged_in"):
        return jsonify({"error": "unauthorized"}), 401
    result = {"url": MIDPOINT_URL, "user": MIDPOINT_ADMIN_USER}
    try:
        r = requests.get(
            f"{MIDPOINT_URL}/midpoint/ws/rest/roles",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Accept": "application/json"},
            timeout=5,
        )
        result["http_status"] = r.status_code
        if r.ok:
            raw = r.json().get("object", {}).get("object", [])
            if isinstance(raw, dict):
                raw = [raw]
            result["roles_count"] = len(raw)
            result["roles"] = [
                (o.get("name", {}).get("orig", o.get("name", "?")) if isinstance(o.get("name"), dict) else o.get("name", "?"))
                for o in raw
            ]
        else:
            result["error"] = r.text[:500]
    except Exception as exc:
        result["error"] = str(exc)

    # Test POST (dry run: try creating a test role, then delete it)
    try:
        pr = requests.post(
            f"{MIDPOINT_URL}/midpoint/ws/rest/roles",
            auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            json={"role": {"name": "__dm_test__", "displayName": "DM Test"}},
            timeout=5,
        )
        result["post_status"] = pr.status_code
        result["post_body"]   = pr.text[:800]
        if pr.status_code in (200, 201):
            loc = pr.headers.get("Location", "")
            oid = loc.rstrip("/").split("/")[-1]
            if oid:
                requests.delete(
                    f"{MIDPOINT_URL}/midpoint/ws/rest/roles/{oid}",
                    auth=(MIDPOINT_ADMIN_USER, MIDPOINT_ADMIN_PASS),
                    timeout=5,
                )
                result["post_status"] = "201+deleted"
    except Exception as exc:
        result["post_error"] = str(exc)

    return jsonify(result)


# ── API key auth decorator ────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = (request.headers.get("X-Governance-API-Key")
               or request.headers.get("X-Api-Key", ""))
        if key != GOVERNANCE_API_KEY:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


# ── Unmask admin UI ───────────────────────────────────────────────────────────

@app.get("/unmask")
@login_required
def unmask_list():
    status_filter = request.args.get("status", "pending")
    conn          = get_db()
    sessions      = qrows(conn,
        "SELECT * FROM unmask_sessions WHERE status = %s ORDER BY requested_at DESC",
        (status_filter,))
    pending_count = scalar(conn,
        "SELECT COUNT(*) FROM unmask_sessions WHERE status = 'pending'")
    conn.close()
    return render_template("unmask.html", sessions=sessions,
                           status_filter=status_filter, pending_count=pending_count,
                           reason_codes=UNMASK_REASON_CODES, all_fields=UNMASK_FIELDS)


@app.post("/unmask/<token_id>/approve")
@login_required
def unmask_approve(token_id):
    conn = get_db()
    execute(conn,
        """UPDATE unmask_sessions
           SET status = 'approved', reviewed_at = NOW(), reviewed_by = %s,
               expires_at = NOW() + INTERVAL '15 minutes'
           WHERE id = %s AND status = 'pending'""",
        (ADMIN_USER, token_id))
    conn.commit()
    conn.close()
    flash("Unmask session approved — valid for 15 minutes", "success")
    return redirect(url_for("unmask_list"))


@app.post("/unmask/<token_id>/reject")
@login_required
def unmask_reject(token_id):
    conn = get_db()
    execute(conn,
        """UPDATE unmask_sessions
           SET status = 'rejected', reviewed_at = NOW(), reviewed_by = %s
           WHERE id = %s AND status = 'pending'""",
        (ADMIN_USER, token_id))
    conn.commit()
    conn.close()
    flash("Unmask session rejected", "success")
    return redirect(url_for("unmask_list"))


# ── Unmask API (frontend-hub, API key auth) ───────────────────────────────────

@app.post("/api/unmask/request")
@require_api_key
def api_unmask_request():
    body        = request.get_json(force=True) or {}
    user_id     = body.get("user_id", "")
    username    = body.get("username", "")
    customer_id = body.get("customer_id", "")
    fields      = body.get("fields", [])
    reason_code = body.get("reason_code", "")
    ticket_ref  = body.get("ticket_ref", "")
    notes       = body.get("notes", "")
    if not username or not customer_id or not fields or not reason_code:
        return jsonify({"error": "username, customer_id, fields, reason_code required"}), 400
    conn = get_db()
    row  = qone(conn,
        """INSERT INTO unmask_sessions
           (user_id, username, customer_id, fields, reason_code, ticket_ref, notes)
           VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
        (user_id, username, customer_id, fields, reason_code, ticket_ref, notes))
    conn.commit()
    conn.close()
    return jsonify({"token_id": str(row["id"]), "status": "pending"})


@app.get("/api/unmask/status/<token_id>")
@require_api_key
def api_unmask_status(token_id):
    conn = get_db()
    row  = qone(conn, "SELECT * FROM unmask_sessions WHERE id = %s", (token_id,))
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "token_id":   str(row["id"]),
        "status":     row["status"],
        "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
        "fields":     list(row["fields"] or []),
        "consumed":   row["used_at"] is not None,
    })


# ── Unmask validation (Kong, internal network, no auth) ───────────────────────

@app.get("/unmask/validate/<token_id>")
def unmask_validate(token_id):
    customer_id = request.args.get("customer_id", "")
    conn = get_db()
    row  = qone(conn, "SELECT * FROM unmask_sessions WHERE id = %s", (token_id,))
    if not row:
        conn.close()
        return jsonify({"valid": False, "reason": "not_found"})
    if row["status"] != "approved":
        conn.close()
        return jsonify({"valid": False, "reason": row["status"]})
    expired = scalar(conn,
        "SELECT expires_at IS NOT NULL AND expires_at < NOW() "
        "FROM unmask_sessions WHERE id = %s", (token_id,))
    if expired:
        conn.close()
        return jsonify({"valid": False, "reason": "expired"})
    if customer_id and row["customer_id"] != customer_id:
        conn.close()
        return jsonify({"valid": False, "reason": "customer_mismatch"})
    if not row["first_used_at"]:
        execute(conn,
            "UPDATE unmask_sessions SET first_used_at = NOW(), used_at = NOW() WHERE id = %s",
            (token_id,))
        conn.commit()
    conn.close()
    return jsonify({
        "valid":       True,
        "fields":      list(row["fields"] or []),
        "reason_code": row["reason_code"],
        "username":    row["username"],
    })


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    for i in range(10):
        try:
            init_db()
            print("Database initialised ✓")
            break
        except Exception as exc:
            wait = 2 ** i
            print(f"DB not ready ({exc}), retry in {wait}s…")
            time.sleep(wait)
    app.run(host="0.0.0.0", port=8888, debug=False)
