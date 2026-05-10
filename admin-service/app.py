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
            added_by     TEXT DEFAULT 'system',
            added_at     TEXT NOT NULL
        )""",
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
    app_role_rows = qrows(conn,
        "SELECT app_id, role FROM app_roles ORDER BY app_id, role"
    )
    purpose_rows  = qrows(conn,
        "SELECT role, purpose, field FROM purpose_policies ORDER BY role, purpose, field"
    )
    rule_rows     = qrows(conn,
        "SELECT id, name, priority, condition_roles, condition_tiers, condition_purposes, "
        "condition_channels, condition_in_working_hours, action, fields, enabled "
        "FROM masking_rules ORDER BY priority, id"
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
    conn     = get_db()
    apps     = qrows(conn, "SELECT * FROM apps ORDER BY app_id")
    rows     = qrows(conn, "SELECT app_id, role FROM app_roles ORDER BY app_id, role")
    conn.close()
    app_role_map = {}
    for r in rows:
        app_role_map.setdefault(r["app_id"], []).append(r["role"])
    return render_template("apps.html", apps=apps, app_role_map=app_role_map,
                           roles=ROLES, mp_source=False)


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
            "INSERT INTO apps (app_id, name, upstream_url, description, added_by, added_at) "
            "VALUES (%s, %s, %s, %s, 'admin', %s)",
            (app_id, name, url, desc, datetime.utcnow().isoformat()))
        conn.commit()
        flash(f"App '{app_id}' registered. Configure its allowed roles below.", "success")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"App ID '{app_id}' already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("apps_list"))


@app.post("/apps/remove/<app_id>")
@login_required
def apps_remove(app_id):
    conn = get_db()
    execute(conn, "DELETE FROM apps WHERE app_id = %s", (app_id,))
    conn.commit()
    conn.close()
    flash(f"App '{app_id}' removed from registry.", "success")
    return redirect(url_for("apps_list"))


@app.post("/apps/<app_id>/roles/save")
@login_required
def apps_roles_save(app_id):
    """DB-only fallback — only effective when midPoint is unreachable."""
    selected = [r for r in ROLES if request.form.get(f"role__{r}")]
    conn     = get_db()
    execute(conn, "DELETE FROM app_roles WHERE app_id = %s", (app_id,))
    if selected:
        executemany(conn, "INSERT INTO app_roles (app_id, role) VALUES (%s, %s)",
                    [(app_id, r) for r in selected])
    conn.commit()
    conn.close()
    sync_to_opa()
    flash(f"Roles saved for '{app_id}' — OPA will reload within 60s", "success")
    return redirect(url_for("apps_list"))


GOVERNANCE_API_KEY = os.environ.get("GOVERNANCE_API_KEY", "governance-internal-key")


@app.get("/api/apps")
def api_apps_list():
    """JSON list of registered apps — consumed by frontend-hub for dynamic discovery."""
    key = request.headers.get("X-Governance-API-Key") or request.headers.get("X-Api-Key", "")
    if key != GOVERNANCE_API_KEY:
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    rows = qrows(conn,
        "SELECT app_id, name, upstream_url, description FROM apps ORDER BY app_id")
    conn.close()
    return jsonify([dict(r) for r in rows])


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
