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

_DEFAULT_APPS = [
    ("crm",     "CRM System",      "http://crm-mock:5000",     "Main CRM backend"),
    ("billing", "Billing System",  "http://billing-mock:5001", "Billing backend"),
]

# Roles allowed per app by default — matches existing policy intent
_DEFAULT_APP_ROLES = [
    # CRM: all internal roles (partners excluded from unmask paths by policy)
    ("crm", "agent"), ("crm", "supervisor"), ("crm", "vip_agent"), ("crm", "admin"),
    ("crm", "care_l1"), ("crm", "care_l2"), ("crm", "care_supervisor"),
    ("crm", "noc_operator"), ("crm", "field_technician"), ("crm", "roaming_ops"),
    ("crm", "billing_agent"), ("crm", "fraud_analyst"), ("crm", "compliance_officer"),
    ("crm", "audit_viewer"), ("crm", "vip_care"), ("crm", "data_admin"),
    ("crm", "partner"), ("crm", "b2b_partner"), ("crm", "mvno_partner"),
    # Billing: financial roles + compliance + audit
    ("billing", "billing_agent"), ("billing", "admin"), ("billing", "data_admin"),
    ("billing", "fraud_analyst"), ("billing", "compliance_officer"),
    ("billing", "audit_viewer"), ("billing", "supervisor"), ("billing", "care_supervisor"),
    ("billing", "roaming_ops"),
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

    return {
        "customer_tiers":     customer_tiers,
        "role_masked_fields": role_masked_fields,
        "backends":           backends,
        "app_roles":          app_roles,
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


# ── Application registry ──────────────────────────────────────────────────────

@app.get("/apps")
@login_required
def apps_list():
    conn          = get_db()
    apps          = qrows(conn, "SELECT * FROM apps ORDER BY app_id")
    app_role_rows = qrows(conn, "SELECT app_id, role FROM app_roles ORDER BY app_id, role")
    conn.close()
    app_role_map = {}
    for row in app_role_rows:
        app_role_map.setdefault(row["app_id"], set()).add(row["role"])
    return render_template("apps.html", apps=apps, app_role_map=app_role_map, roles=ROLES)


@app.post("/apps/add")
@login_required
def app_add():
    app_id = (request.form.get("app_id")       or "").strip().lower().replace(" ", "_")
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
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (app_id, name, url, desc, ADMIN_USER, datetime.utcnow().isoformat()),
        )
        conn.commit()
        flash(f"Application '{app_id}' registered", "success")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash(f"App ID '{app_id}' already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("apps_list"))


@app.post("/apps/remove/<app_id>")
@login_required
def app_remove(app_id):
    conn = get_db()
    execute(conn, "DELETE FROM apps WHERE app_id = %s", (app_id,))
    conn.commit()
    conn.close()
    ok, _ = sync_to_opa()
    flash(f"Application '{app_id}' removed" + (" – OPA synced ✓" if ok else ""), "success")
    return redirect(url_for("apps_list"))


@app.post("/apps/<app_id>/roles/save")
@login_required
def app_roles_save(app_id):
    selected = [r for r in ROLES if request.form.get(f"role__{r}")]
    conn     = get_db()
    execute(conn, "DELETE FROM app_roles WHERE app_id = %s", (app_id,))
    if selected:
        executemany(conn,
            "INSERT INTO app_roles (app_id, role) VALUES (%s, %s)",
            [(app_id, r) for r in selected],
        )
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash(
        f"Access roles for '{app_id}' updated "
        + ("– OPA synced ✓" if ok else f"– sync failed: {msg}"),
        "success" if ok else "warning",
    )
    return redirect(url_for("apps_list"))


# ── Keycloak Admin API client ─────────────────────────────────────────────────

def kc_admin_token():
    resp = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
        data={
            "client_id":  "admin-cli",
            "grant_type": "password",
            "username":   KEYCLOAK_ADMIN_USER,
            "password":   KEYCLOAK_ADMIN_PASS,
        },
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _kc(method, path, token, **kwargs):
    resp = requests.request(
        method,
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}{path}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
        **kwargs,
    )
    resp.raise_for_status()
    return resp


def kc_get(path, token):
    return _kc("GET", path, token).json()


def kc_post(path, token, payload):
    return _kc("POST", path, token, json=payload)


def kc_put(path, token, payload):
    return _kc("PUT", path, token, json=payload)


def kc_delete(path, token, payload=None):
    return _kc("DELETE", path, token, json=payload)


# ── User lifecycle management ─────────────────────────────────────────────────

@app.get("/users")
@login_required
def users_list():
    users = []
    error = None
    try:
        token     = kc_admin_token()
        raw_users = kc_get("/users?max=200&briefRepresentation=false", token)
        known     = set(ROLES)
        for u in raw_users:
            try:
                role_maps    = kc_get(f"/users/{u['id']}/role-mappings/realm", token)
                u["app_roles"] = [r["name"] for r in role_maps if r["name"] in known]
            except Exception:
                u["app_roles"] = []
            users.append(u)
    except Exception as exc:
        error = str(exc)
    return render_template("users.html", users=users, roles=ROLES, error=error)


@app.post("/users/add")
@login_required
def user_add():
    username  = (request.form.get("username")   or "").strip()
    email     = (request.form.get("email")      or "").strip()
    first     = (request.form.get("first_name") or "").strip()
    last      = (request.form.get("last_name")  or "").strip()
    password  = (request.form.get("password")   or "").strip()
    role_name = (request.form.get("role")       or "").strip()
    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for("users_list"))
    if role_name and role_name not in ROLES:
        flash(f"Unknown role '{role_name}'", "danger")
        return redirect(url_for("users_list"))
    try:
        token = kc_admin_token()
        kc_post("/users", token, {
            "username":    username,
            "email":       email or None,
            "firstName":   first or None,
            "lastName":    last or None,
            "enabled":     True,
            "credentials": [{"type": "password", "value": password, "temporary": True}],
        })
        if role_name:
            found = kc_get(f"/users?username={username}&exact=true", token)
            if found:
                all_roles = kc_get("/roles", token)
                role_rep  = next((r for r in all_roles if r["name"] == role_name), None)
                if role_rep:
                    kc_post(f"/users/{found[0]['id']}/role-mappings/realm", token, [role_rep])
        flash(
            f"User '{username}' created"
            + (f" with role '{role_name}'" if role_name else "")
            + " — temporary password set",
            "success",
        )
    except Exception as exc:
        flash(f"Failed to create user: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/roles/save")
@login_required
def user_roles_save(user_id):
    selected = [r for r in ROLES if request.form.get(f"role__{r}")]
    username = request.form.get("username", user_id)
    try:
        token   = kc_admin_token()
        current = kc_get(f"/users/{user_id}/role-mappings/realm", token)
        if current:
            kc_delete(f"/users/{user_id}/role-mappings/realm", token, current)
        if selected:
            all_roles = kc_get("/roles", token)
            role_reps = [r for r in all_roles if r["name"] in selected]
            kc_post(f"/users/{user_id}/role-mappings/realm", token, role_reps)
        flash(f"Roles updated for '{username}'", "success")
    except Exception as exc:
        flash(f"Failed to update roles: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/offboard")
@login_required
def user_offboard(user_id):
    username = request.form.get("username", user_id)
    try:
        token = kc_admin_token()
        kc_put(f"/users/{user_id}", token, {"enabled": False})
        flash(
            f"User '{username}' disabled — all active sessions immediately revoked",
            "success",
        )
    except Exception as exc:
        flash(f"Failed to offboard '{username}': {exc}", "danger")
    return redirect(url_for("users_list"))


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
