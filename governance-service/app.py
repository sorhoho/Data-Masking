import os
import threading
import time
import uuid
from datetime import datetime, timezone
from functools import wraps

import psycopg2
import psycopg2.extras
import requests
from flask import (Flask, flash, jsonify, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "governance-secret")

KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM        = os.environ.get("KEYCLOAK_REALM", "demo")
KEYCLOAK_ADMIN_USER   = os.environ.get("KEYCLOAK_ADMIN_USER", "admin")
KEYCLOAK_ADMIN_PASS   = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin")
DATABASE_URL          = os.environ.get("DATABASE_URL", "postgresql://adminuser:admin_pass@postgres:5432/admindb")
ADMIN_USER            = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS            = os.environ.get("ADMIN_PASSWORD", "admin123")
LOG_DASHBOARD_URL     = os.environ.get("LOG_DASHBOARD_URL", "http://log-dashboard:9000/log")
GOVERNANCE_API_KEY    = os.environ.get("GOVERNANCE_API_KEY", "governance-internal-key")

UNMASK_REASON_CODES = [
    "FRAUD_INVESTIGATION",
    "COMPLIANCE_AUDIT",
    "LEGAL_HOLD",
    "CUSTOMER_DISPUTE",
    "TECHNICAL_ESCALATION",
    "REGULATOR_REQUEST",
]

UNMASK_FIELDS = [
    "name", "msisdn", "email", "national_id", "address",
    "last_call_duration", "data_roaming_gb", "last_location",
]

GOVERNED_ROLES = [
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


# ── Database ──────────────────────────────────────────────────────────────────

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


def init_db():
    conn = get_db()
    stmts = [
        """CREATE TABLE IF NOT EXISTS governance_role_requests (
            id             SERIAL PRIMARY KEY,
            user_id        VARCHAR(255) NOT NULL,
            username       VARCHAR(255) NOT NULL,
            email          VARCHAR(255) DEFAULT '',
            request_type   VARCHAR(50)  NOT NULL,
            requested_role VARCHAR(100),
            old_role       VARCHAR(100),
            status         VARCHAR(50)  NOT NULL DEFAULT 'pending',
            requested_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            reviewed_at    TIMESTAMPTZ,
            reviewed_by    VARCHAR(255),
            expires_at     TIMESTAMPTZ,
            notes          TEXT DEFAULT '',
            revoked_at     TIMESTAMPTZ
        )""",
        """CREATE TABLE IF NOT EXISTS governance_access_campaigns (
            id           SERIAL PRIMARY KEY,
            name         VARCHAR(255) NOT NULL,
            description  TEXT DEFAULT '',
            due_date     DATE NOT NULL,
            status       VARCHAR(50) NOT NULL DEFAULT 'active',
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by   VARCHAR(255) NOT NULL,
            completed_at TIMESTAMPTZ
        )""",
        """CREATE TABLE IF NOT EXISTS governance_review_items (
            id          SERIAL PRIMARY KEY,
            campaign_id INT          NOT NULL REFERENCES governance_access_campaigns(id),
            user_id     VARCHAR(255) NOT NULL,
            username    VARCHAR(255) NOT NULL,
            email       VARCHAR(255) DEFAULT '',
            role_name   VARCHAR(100) NOT NULL,
            decision    VARCHAR(50) NOT NULL DEFAULT 'pending',
            decided_at  TIMESTAMPTZ,
            decided_by  VARCHAR(255)
        )""",
        """CREATE TABLE IF NOT EXISTS governance_sod_rules (
            id         SERIAL PRIMARY KEY,
            role_a     VARCHAR(100) NOT NULL,
            role_b     VARCHAR(100) NOT NULL,
            reason     TEXT DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(role_a, role_b)
        )""",
        """CREATE TABLE IF NOT EXISTS unmask_sessions (
            id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
            user_id      VARCHAR(255) NOT NULL,
            username     VARCHAR(255) NOT NULL,
            customer_id  VARCHAR(255) NOT NULL,
            fields       JSONB        NOT NULL DEFAULT '[]',
            reason_code  VARCHAR(100) NOT NULL,
            ticket_ref   VARCHAR(255) DEFAULT '',
            notes        TEXT         DEFAULT '',
            status       VARCHAR(50)  NOT NULL DEFAULT 'pending',
            requested_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            reviewed_at  TIMESTAMPTZ,
            reviewed_by  VARCHAR(255),
            expires_at   TIMESTAMPTZ,
            first_used_at TIMESTAMPTZ,
            used_at      TIMESTAMPTZ
        )""",
        # Migration: add used_at to existing tables
        "ALTER TABLE unmask_sessions ADD COLUMN IF NOT EXISTS used_at TIMESTAMPTZ",
        """CREATE TABLE IF NOT EXISTS access_packages (
            id                 SERIAL PRIMARY KEY,
            name               TEXT    NOT NULL,
            description        TEXT    DEFAULT '',
            roles              TEXT[]  NOT NULL DEFAULT '{}',
            max_duration_hours INT,
            requires_approval  BOOLEAN NOT NULL DEFAULT true,
            enabled            BOOLEAN NOT NULL DEFAULT true,
            created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            created_by         TEXT    NOT NULL DEFAULT 'system'
        )""",
        """CREATE TABLE IF NOT EXISTS access_package_requests (
            id            SERIAL  PRIMARY KEY,
            package_id    INT     NOT NULL REFERENCES access_packages(id),
            package_name  TEXT    NOT NULL,
            user_id       TEXT    NOT NULL,
            username      TEXT    NOT NULL,
            email         TEXT    DEFAULT '',
            justification TEXT    DEFAULT '',
            status        TEXT    NOT NULL DEFAULT 'pending',
            requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            reviewed_at   TIMESTAMPTZ,
            reviewed_by   TEXT,
            expires_at    TIMESTAMPTZ,
            revoked_at    TIMESTAMPTZ,
            granted_roles TEXT[]  NOT NULL DEFAULT '{}'
        )""",
    ]
    for stmt in stmts:
        execute(conn, stmt)

    # Seed default SoD rules once
    if not qone(conn, "SELECT 1 FROM governance_sod_rules LIMIT 1"):
        defaults = [
            # Legacy role conflicts
            ("agent",              "admin",              "Agents must not hold admin privileges"),
            ("agent",              "vip_agent",          "Agents must not bypass their own masking"),
            ("partner",            "admin",              "External partners must not be admins"),
            ("partner",            "vip_agent",          "External partners must not access VIP data"),
            # Care vs privileged — front-line agents can't self-escalate
            ("care_l1",            "fraud_analyst",      "L1 agents must not conduct fraud investigations"),
            ("care_l1",            "compliance_officer", "L1 agents must not hold compliance authority"),
            ("care_l1",            "data_admin",         "L1 agents must not have data admin access"),
            ("care_l2",            "data_admin",         "L2 agents must not have data admin access"),
            # Audit independence — auditors cannot also be admins
            ("audit_viewer",       "data_admin",         "Auditors must be independent of data administration"),
            ("audit_viewer",       "compliance_officer", "Audit and compliance must be separate functions"),
            # External partner restrictions — no internal privileged roles
            ("b2b_partner",        "data_admin",         "External B2B partners must not be data admins"),
            ("b2b_partner",        "fraud_analyst",      "External partners must not access fraud tools"),
            ("b2b_partner",        "compliance_officer", "External partners must not hold compliance authority"),
            ("mvno_partner",       "data_admin",         "MVNO partners must not be data admins"),
            ("mvno_partner",       "fraud_analyst",      "MVNO partners must not access fraud investigation tools"),
            # Operations separation — technical and financial functions must be separate
            ("field_technician",   "billing_agent",      "Technical and financial operations must be separated"),
            ("noc_operator",       "billing_agent",      "Network ops and billing must be separated"),
            ("billing_agent",      "fraud_analyst",      "Billing agents must not investigate their own processes"),
            # Roaming ops is external-facing — no internal admin access
            ("roaming_ops",        "data_admin",         "Roaming ops must not have unrestricted data access"),
        ]
        for role_a, role_b, reason in defaults:
            execute(conn,
                "INSERT INTO governance_sod_rules (role_a, role_b, reason) VALUES (%s,%s,%s) "
                "ON CONFLICT DO NOTHING",
                (role_a, role_b, reason))

    _DEFAULT_PACKAGES = [
        ("Front-line Care Agent",
         "Standard care operations: L1 support with billing visibility",
         ["care_l1", "billing_agent"], None, True),
        ("Care Operations Lead",
         "L2 care with supervisor access for escalation handling",
         ["care_l2", "care_supervisor"], None, True),
        ("Fraud Analyst On-Call",
         "Time-limited fraud investigation and compliance access — 8-hour window",
         ["fraud_analyst", "compliance_officer"], 8, True),
        ("Technical Operations",
         "NOC and field technician access for infrastructure teams",
         ["noc_operator", "field_technician"], None, True),
        ("Audit Compliance Review",
         "Read-only audit and compliance access — 24-hour window",
         ["audit_viewer", "compliance_officer"], 24, True),
        ("VIP Care Specialist",
         "Elevated VIP customer care with supervisor capabilities",
         ["vip_care", "care_supervisor"], None, True),
        ("External Partner Access",
         "Standard-tier B2B partner data read access",
         ["b2b_partner"], None, True),
        ("Roaming Operations",
         "Roaming and network operations team access",
         ["roaming_ops", "noc_operator"], None, True),
    ]
    if not qone(conn, "SELECT 1 FROM access_packages LIMIT 1"):
        for pkg_name, pkg_desc, pkg_roles, pkg_dur, pkg_appr in _DEFAULT_PACKAGES:
            execute(conn,
                """INSERT INTO access_packages
                   (name, description, roles, max_duration_hours, requires_approval, enabled, created_by)
                   VALUES (%s, %s, %s, %s, %s, true, 'system')""",
                (pkg_name, pkg_desc, pkg_roles, pkg_dur, pkg_appr))

    conn.commit()
    conn.close()


# ── Separation of Duties ─────────────────────────────────────────────────────

def sod_check(user_id, requested_role):
    """Return (ok, reason). ok=False means the assignment would violate a SoD rule."""
    if not requested_role:
        return True, None
    try:
        existing = kc_get_user_roles(user_id)
    except Exception:
        return True, None  # can't check — let through, admin can verify manually

    conn = get_db()
    rules = qrows(conn, "SELECT * FROM governance_sod_rules")
    conn.close()

    for rule in rules:
        pair = {rule["role_a"], rule["role_b"]}
        for held in existing:
            if {held, requested_role} == pair:
                return False, (
                    f"SoD violation: '{held}' and '{requested_role}' are incompatible "
                    f"— {rule['reason']}"
                )
    return True, None


# ── Keycloak Admin REST API ───────────────────────────────────────────────────

def kc_admin_token():
    resp = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id":  "admin-cli",
            "username":   KEYCLOAK_ADMIN_USER,
            "password":   KEYCLOAK_ADMIN_PASS,
        },
        timeout=5,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def kc_headers():
    return {"Authorization": f"Bearer {kc_admin_token()}"}


def kc_get_users():
    resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users?max=200",
        headers=kc_headers(), timeout=5,
    )
    resp.raise_for_status()
    return resp.json()


def kc_get_user_roles(user_id):
    resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers=kc_headers(), timeout=5,
    )
    resp.raise_for_status()
    return [r["name"] for r in resp.json() if r["name"] in GOVERNED_ROLES]


def kc_get_role(role_name):
    resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{role_name}",
        headers=kc_headers(), timeout=5,
    )
    resp.raise_for_status()
    return resp.json()


def kc_assign_role(user_id, role_name):
    role = kc_get_role(role_name)
    resp = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers=kc_headers(), json=[role], timeout=5,
    )
    resp.raise_for_status()


def kc_revoke_role(user_id, role_name):
    role = kc_get_role(role_name)
    resp = requests.delete(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/role-mappings/realm",
        headers=kc_headers(), json=[role], timeout=5,
    )
    resp.raise_for_status()


def kc_revoke_all_roles(user_id):
    roles = kc_get_user_roles(user_id)
    for role in roles:
        kc_revoke_role(user_id, role)
    return roles


def kc_create_user(username, email, first, last, password):
    resp = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users",
        headers=kc_headers(), timeout=5,
        json={
            "username":    username,
            "email":       email,
            "firstName":   first,
            "lastName":    last,
            "enabled":     True,
            "credentials": [{"type": "password", "value": password, "temporary": True}],
        },
    )
    resp.raise_for_status()


def kc_find_user(username):
    resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users"
        f"?username={username}&exact=true",
        headers=kc_headers(), timeout=5,
    )
    resp.raise_for_status()
    found = resp.json()
    return found[0] if found else None


def kc_disable_user(user_id):
    resp = requests.put(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}",
        headers=kc_headers(), timeout=5,
        json={"enabled": False},
    )
    resp.raise_for_status()


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_event(event_type, details):
    def _send():
        try:
            requests.post(LOG_DASHBOARD_URL, json={
                "service":   "governance-service",
                "event":     event_type,
                "details":   details,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()


# ── Template context (sidebar badge counts) ──────────────────────────────────

@app.context_processor
def sidebar_counts():
    try:
        conn = get_db()
        pc  = scalar(conn, "SELECT COUNT(*) FROM governance_role_requests WHERE status='pending'")
        upc = scalar(conn, "SELECT COUNT(*) FROM unmask_sessions WHERE status='pending'")
        pkgc = scalar(conn, "SELECT COUNT(*) FROM access_package_requests WHERE status='pending'")
        conn.close()
        return {"pending_count": pc or 0, "unmask_pending_count": upc or 0, "pkg_pending_count": pkgc or 0}
    except Exception:
        return {"pending_count": 0, "unmask_pending_count": 0, "pkg_pending_count": 0}


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


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/")
@login_required
def dashboard():
    conn = get_db()
    pending        = scalar(conn, "SELECT COUNT(*) FROM governance_role_requests WHERE status='pending'")
    active_reviews = scalar(conn, "SELECT COUNT(*) FROM governance_access_campaigns WHERE status='active'")
    pending_unmask = scalar(conn, "SELECT COUNT(*) FROM unmask_sessions WHERE status='pending'")
    sod_rules      = scalar(conn, "SELECT COUNT(*) FROM governance_sod_rules")
    expiring_soon  = scalar(conn,
        """SELECT COUNT(*) FROM governance_role_requests
           WHERE status='approved' AND expires_at IS NOT NULL
             AND expires_at BETWEEN NOW() AND NOW() + INTERVAL '7 days'
             AND revoked_at IS NULL""")
    recent = qrows(conn, "SELECT * FROM governance_role_requests ORDER BY requested_at DESC LIMIT 10")
    conn.close()
    return render_template("dashboard.html",
                           pending=pending, active_reviews=active_reviews,
                           pending_unmask=pending_unmask, sod_rules=sod_rules,
                           expiring_soon=expiring_soon, recent=recent)


# ── Role Requests ─────────────────────────────────────────────────────────────

@app.get("/requests")
@login_required
def requests_list():
    status_filter = request.args.get("status", "pending")
    conn  = get_db()
    rows  = qrows(conn,
        "SELECT * FROM governance_role_requests WHERE status=%s ORDER BY requested_at DESC",
        (status_filter,))
    conn.close()
    try:
        kc_users = kc_get_users()
    except Exception:
        kc_users = []
    return render_template("requests.html", rows=rows, status=status_filter,
                           kc_users=kc_users, roles=GOVERNED_ROLES)


@app.post("/requests/new")
@login_required
def request_new():
    user_id        = request.form["user_id"]
    username       = request.form["username"]
    email          = request.form.get("email", "")
    request_type   = request.form["request_type"]
    requested_role = request.form.get("requested_role") or None
    old_role       = request.form.get("current_role") or None
    expires_at     = request.form.get("expires_at") or None
    notes          = request.form.get("notes", "")

    conn = get_db()
    execute(conn,
        """INSERT INTO governance_role_requests
           (user_id, username, email, request_type, requested_role, old_role, expires_at, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (user_id, username, email, request_type, requested_role, old_role, expires_at, notes))
    conn.commit()
    conn.close()
    log_event("role_request_submitted",
              {"username": username, "type": request_type, "requested_role": requested_role})
    flash(f"Request submitted for {username}", "success")
    return redirect(url_for("requests_list"))


@app.post("/requests/<int:req_id>/approve")
@login_required
def request_approve(req_id):
    conn = get_db()
    row  = qone(conn, "SELECT * FROM governance_role_requests WHERE id=%s", (req_id,))
    conn.close()
    if not row:
        flash("Request not found", "danger")
        return redirect(url_for("requests_list"))

    try:
        if row["request_type"] == "offboarding":
            revoked = kc_revoke_all_roles(row["user_id"])
            log_event("offboarding_executed",
                      {"username": row["username"], "revoked_roles": revoked})
        else:
            ok, reason = sod_check(row["user_id"], row["requested_role"])
            if not ok:
                flash(f"Blocked: {reason}", "danger")
                return redirect(url_for("requests_list"))
            if row["request_type"] == "change" and row["old_role"]:
                kc_revoke_role(row["user_id"], row["old_role"])
            if row["requested_role"]:
                kc_assign_role(row["user_id"], row["requested_role"])
            log_event("role_assigned",
                      {"username": row["username"], "role": row["requested_role"],
                       "type": row["request_type"]})

        conn = get_db()
        execute(conn,
            "UPDATE governance_role_requests SET status='approved', reviewed_at=NOW(), reviewed_by=%s WHERE id=%s",
            (ADMIN_USER, req_id))
        conn.commit()
        conn.close()
        flash(f"Approved: {row['username']}", "success")
    except Exception as e:
        flash(f"Keycloak error: {e}", "danger")

    return redirect(url_for("requests_list"))


@app.post("/requests/<int:req_id>/reject")
@login_required
def request_reject(req_id):
    conn = get_db()
    row  = qone(conn, "SELECT username FROM governance_role_requests WHERE id=%s", (req_id,))
    execute(conn,
        "UPDATE governance_role_requests SET status='rejected', reviewed_at=NOW(), reviewed_by=%s WHERE id=%s",
        (ADMIN_USER, req_id))
    conn.commit()
    conn.close()
    if row:
        log_event("role_request_rejected", {"username": row["username"]})
    flash("Request rejected", "warning")
    return redirect(url_for("requests_list"))


# ── Application registry ─────────────────────────────────────────────────────

@app.get("/apps")
@login_required
def apps_list():
    conn          = get_db()
    apps          = qrows(conn, "SELECT * FROM apps ORDER BY app_id")
    app_role_rows = qrows(conn, "SELECT app_id, role FROM app_roles ORDER BY app_id, role")
    conn.close()
    app_role_map = {}
    for row in app_role_rows:
        app_role_map.setdefault(row["app_id"], []).append(row["role"])
    return render_template("apps.html", apps=apps, app_role_map=app_role_map, roles=GOVERNED_ROLES)


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
            "VALUES (%s, %s, %s, %s, %s, NOW())",
            (app_id, name, url, desc, ADMIN_USER),
        )
        conn.commit()
        flash(f"Application '{app_id}' registered — OPA will sync within 60 s", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Failed to register app: {e}", "danger")
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
    flash(f"Application '{app_id}' removed — OPA will sync within 60 s", "success")
    return redirect(url_for("apps_list"))


@app.post("/apps/<app_id>/roles/save")
@login_required
def app_roles_save(app_id):
    selected = [r for r in GOVERNED_ROLES if request.form.get(f"role__{r}")]
    conn     = get_db()
    execute(conn, "DELETE FROM app_roles WHERE app_id = %s", (app_id,))
    if selected:
        for role in selected:
            execute(conn, "INSERT INTO app_roles (app_id, role) VALUES (%s, %s)", (app_id, role))
    conn.commit()
    conn.close()
    flash(f"Access roles for '{app_id}' updated — OPA will sync within 60 s", "success")
    return redirect(url_for("apps_list"))


# ── Users & Offboarding ───────────────────────────────────────────────────────

@app.get("/users")
@login_required
def users_list():
    users = []
    error = None
    try:
        users = kc_get_users()
        for u in users:
            u["governed_roles"] = kc_get_user_roles(u["id"])
    except Exception as e:
        error = str(e)
        flash(f"Keycloak unavailable: {e}", "danger")
    return render_template("users.html", users=users, roles=GOVERNED_ROLES, error=error)


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
    try:
        kc_create_user(username, email or None, first or None, last or None, password)
        if role_name and role_name in GOVERNED_ROLES:
            found = kc_find_user(username)
            if found:
                kc_assign_role(found["id"], role_name)
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
    selected = [r for r in GOVERNED_ROLES if request.form.get(f"role__{r}")]
    username = request.form.get("username", user_id)
    try:
        current = kc_get_user_roles(user_id)
        for role in current:
            kc_revoke_role(user_id, role)
        for role in selected:
            kc_assign_role(user_id, role)
        flash(f"Roles updated for '{username}'", "success")
    except Exception as exc:
        flash(f"Failed to update roles: {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/offboard")
@login_required
def offboard_user(user_id):
    username = request.form.get("username", user_id)
    notes    = request.form.get("notes", "Admin-initiated offboarding")
    try:
        kc_disable_user(user_id)
        conn = get_db()
        execute(conn,
            """INSERT INTO governance_role_requests
               (user_id, username, request_type, notes, status, reviewed_by, reviewed_at)
               VALUES (%s,%s,'offboarding',%s,'approved',%s,NOW())""",
            (user_id, username, notes, ADMIN_USER))
        conn.commit()
        conn.close()
        flash(f"User '{username}' disabled — all active sessions immediately revoked", "success")
    except Exception as exc:
        flash(f"Failed to offboard '{username}': {exc}", "danger")
    return redirect(url_for("users_list"))


@app.post("/users/<user_id>/request-change")
@login_required
def request_role_change(user_id):
    username   = request.form.get("username", user_id)
    email      = request.form.get("email", "")
    old_role   = request.form.get("current_role") or None
    new_role   = request.form.get("new_role") or None
    expires_at = request.form.get("expires_at") or None
    notes      = request.form.get("notes", "")
    req_type   = "onboarding" if not old_role else "change"
    conn = get_db()
    execute(conn,
        """INSERT INTO governance_role_requests
           (user_id, username, email, request_type, requested_role, old_role, expires_at, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (user_id, username, email, req_type, new_role, old_role, expires_at, notes))
    conn.commit()
    conn.close()
    flash(f"Role change request submitted for {username}", "success")
    return redirect(url_for("requests_list"))


# ── Separation of Duties management ──────────────────────────────────────────

@app.get("/sod")
@login_required
def sod_list():
    conn  = get_db()
    rules = qrows(conn, "SELECT * FROM governance_sod_rules ORDER BY id")
    conn.close()
    return render_template("sod.html", rules=rules, roles=GOVERNED_ROLES)


@app.post("/sod/add")
@login_required
def sod_add():
    role_a = request.form.get("role_a", "").strip()
    role_b = request.form.get("role_b", "").strip()
    reason = request.form.get("reason", "").strip()
    if not role_a or not role_b or role_a == role_b:
        flash("Two distinct roles are required", "danger")
        return redirect(url_for("sod_list"))
    conn = get_db()
    try:
        execute(conn,
            "INSERT INTO governance_sod_rules (role_a, role_b, reason) VALUES (%s,%s,%s)",
            (role_a, role_b, reason))
        conn.commit()
        flash(f"SoD rule added: {role_a} ✕ {role_b}", "success")
        log_event("sod_rule_added", {"role_a": role_a, "role_b": role_b})
    except Exception:
        conn.rollback()
        flash("Rule already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("sod_list"))


@app.post("/sod/<int:rule_id>/delete")
@login_required
def sod_delete(rule_id):
    conn = get_db()
    execute(conn, "DELETE FROM governance_sod_rules WHERE id=%s", (rule_id,))
    conn.commit()
    conn.close()
    flash("SoD rule removed", "warning")
    return redirect(url_for("sod_list"))


# ── Access Reviews ────────────────────────────────────────────────────────────

@app.get("/reviews")
@login_required
def reviews_list():
    conn      = get_db()
    campaigns = qrows(conn, "SELECT * FROM governance_access_campaigns ORDER BY created_at DESC")
    conn.close()
    return render_template("reviews.html", campaigns=campaigns)


@app.post("/reviews/new")
@login_required
def review_new():
    name        = request.form["name"]
    description = request.form.get("description", "")
    due_date    = request.form["due_date"]

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO governance_access_campaigns (name, description, due_date, created_by) "
            "VALUES (%s,%s,%s,%s) RETURNING id",
            (name, description, due_date, ADMIN_USER))
        campaign_id = cur.fetchone()[0]

    try:
        users = kc_get_users()
        for u in users:
            for role in kc_get_user_roles(u["id"]):
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO governance_review_items "
                        "(campaign_id, user_id, username, email, role_name) VALUES (%s,%s,%s,%s,%s)",
                        (campaign_id, u["id"], u.get("username", ""), u.get("email", ""), role))
    except Exception as e:
        flash(f"Warning: partial Keycloak population: {e}", "warning")

    conn.commit()
    conn.close()
    log_event("access_review_created", {"campaign": name, "due_date": due_date})
    flash(f"Access review '{name}' created", "success")
    return redirect(url_for("review_detail", campaign_id=campaign_id))


@app.get("/reviews/<int:campaign_id>")
@login_required
def review_detail(campaign_id):
    conn     = get_db()
    campaign = qone(conn, "SELECT * FROM governance_access_campaigns WHERE id=%s", (campaign_id,))
    items    = qrows(conn,
        "SELECT * FROM governance_review_items WHERE campaign_id=%s ORDER BY username",
        (campaign_id,))
    conn.close()
    if not campaign:
        flash("Campaign not found", "danger")
        return redirect(url_for("reviews_list"))
    pending  = sum(1 for i in items if i["decision"] == "pending")
    return render_template("review_detail.html", campaign=campaign, items=items, pending=pending)


@app.post("/reviews/<int:campaign_id>/decide")
@login_required
def review_decide(campaign_id):
    conn = get_db()
    for key, value in request.form.items():
        if key.startswith("decision_"):
            item_id = int(key.split("_", 1)[1])
            execute(conn,
                "UPDATE governance_review_items SET decision=%s, decided_at=NOW(), decided_by=%s WHERE id=%s",
                (value, ADMIN_USER, item_id))
    conn.commit()
    conn.close()
    flash("Decisions saved", "success")
    return redirect(url_for("review_detail", campaign_id=campaign_id))


@app.post("/reviews/<int:campaign_id>/apply")
@login_required
def review_apply(campaign_id):
    conn  = get_db()
    items = qrows(conn,
        "SELECT * FROM governance_review_items WHERE campaign_id=%s AND decision='revoke'",
        (campaign_id,))
    conn.close()

    revoked, errors = 0, []
    for item in items:
        try:
            kc_revoke_role(item["user_id"], item["role_name"])
            log_event("role_revoked_by_review",
                      {"username": item["username"], "role": item["role_name"]})
            revoked += 1
        except Exception as e:
            errors.append(f"{item['username']}: {e}")

    conn = get_db()
    execute(conn,
        "UPDATE governance_access_campaigns SET status='completed', completed_at=NOW() WHERE id=%s",
        (campaign_id,))
    conn.commit()
    conn.close()

    msg = f"Campaign applied: {revoked} role(s) revoked"
    if errors:
        msg += f". Errors: {'; '.join(errors)}"
    flash(msg, "success" if not errors else "warning")
    log_event("access_review_completed", {"campaign_id": campaign_id, "revoked": revoked})
    return redirect(url_for("reviews_list"))


# ── Approval-based Unmask Sessions ───────────────────────────────────────────

@app.get("/unmask")
@login_required
def unmask_list():
    status_filter = request.args.get("status", "pending")
    conn  = get_db()
    rows  = qrows(conn,
        "SELECT * FROM unmask_sessions WHERE status=%s ORDER BY requested_at DESC",
        (status_filter,))
    conn.close()
    try:
        kc_users = kc_get_users()
    except Exception:
        kc_users = []
    return render_template("unmask.html", rows=rows, status=status_filter,
                           kc_users=kc_users, reason_codes=UNMASK_REASON_CODES,
                           unmask_fields=UNMASK_FIELDS)


@app.post("/unmask/request")
@login_required
def unmask_request():
    user_id     = request.form["user_id"]
    username    = request.form["username"]
    customer_id = request.form["customer_id"]
    reason_code = request.form["reason_code"]
    ticket_ref  = request.form.get("ticket_ref", "").strip()
    notes       = request.form.get("notes", "").strip()
    fields      = request.form.getlist("fields")  # list of field names

    import json as _json
    conn = get_db()
    execute(conn,
        """INSERT INTO unmask_sessions
           (user_id, username, customer_id, fields, reason_code, ticket_ref, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (user_id, username, customer_id, _json.dumps(fields),
         reason_code, ticket_ref, notes))
    conn.commit()
    conn.close()
    log_event("unmask_requested",
              {"username": username, "customer_id": customer_id,
               "reason_code": reason_code, "ticket_ref": ticket_ref})
    flash(f"Unmask request submitted for customer {customer_id} — pending approval", "success")
    return redirect(url_for("unmask_list"))


@app.post("/unmask/<token_id>/approve")
@login_required
def unmask_approve(token_id):
    conn = get_db()
    row  = qone(conn, "SELECT * FROM unmask_sessions WHERE id=%s", (token_id,))
    if not row or row["status"] != "pending":
        conn.close()
        flash("Session not found or not pending", "danger")
        return redirect(url_for("unmask_list"))
    execute(conn,
        """UPDATE unmask_sessions
           SET status='approved', reviewed_at=NOW(), reviewed_by=%s,
               expires_at=NOW() + INTERVAL '15 minutes'
           WHERE id=%s""",
        (ADMIN_USER, token_id))
    conn.commit()
    conn.close()
    log_event("unmask_approved",
              {"token": token_id, "customer_id": row["customer_id"],
               "username": row["username"], "reason_code": row["reason_code"]})
    flash(f"Unmask session approved — valid for 2 hours (token: {token_id})", "success")
    return redirect(url_for("unmask_list", status="approved"))


@app.post("/unmask/<token_id>/reject")
@login_required
def unmask_reject(token_id):
    conn = get_db()
    row  = qone(conn, "SELECT username, customer_id FROM unmask_sessions WHERE id=%s", (token_id,))
    execute(conn,
        "UPDATE unmask_sessions SET status='rejected', reviewed_at=NOW(), reviewed_by=%s WHERE id=%s",
        (ADMIN_USER, token_id))
    conn.commit()
    conn.close()
    if row:
        log_event("unmask_rejected",
                  {"token": token_id, "customer_id": row["customer_id"],
                   "username": row["username"]})
    flash("Unmask request rejected", "warning")
    return redirect(url_for("unmask_list"))


@app.get("/unmask/validate/<token_id>")
def unmask_validate(token_id):
    """Kong calls this to validate an unmask token. Enforces T1: user binding + one-time-use."""
    customer_id     = request.args.get("customer_id", "")
    username_param  = request.args.get("username", "")

    conn = get_db()
    # Must be approved, unexpired, unbound-to-customer, and not yet consumed
    row = qone(conn,
        """SELECT * FROM unmask_sessions
           WHERE id=%s AND status='approved'
             AND expires_at > NOW()
             AND customer_id=%s
             AND used_at IS NULL""",
        (token_id, customer_id))
    if not row:
        conn.close()
        return jsonify({"valid": False, "reason": "not_found_or_expired_or_consumed"})

    # T1: user binding — token must belong to the caller
    if username_param and row["username"] != username_param:
        conn.close()
        log_event("unmask_user_mismatch",
                  {"token": token_id, "expected": row["username"], "got": username_param})
        return jsonify({"valid": False, "reason": "user_mismatch"})

    # T1: one-time-use — mark consumed immediately
    execute(conn,
        "UPDATE unmask_sessions SET used_at=NOW(), first_used_at=COALESCE(first_used_at,NOW()), "
        "status='consumed' WHERE id=%s",
        (token_id,))
    conn.commit()
    conn.close()

    import json as _json
    fields = row["fields"] if isinstance(row["fields"], list) else _json.loads(row["fields"] or "[]")
    log_event("unmask_token_used",
              {"token": token_id, "customer_id": customer_id,
               "username": row["username"], "reason_code": row["reason_code"],
               "fields": fields})
    return jsonify({
        "valid":       True,
        "fields":      fields,
        "reason_code": row["reason_code"],
        "username":    row["username"],
        "expires_at":  row["expires_at"].isoformat() if row["expires_at"] else None,
    })


# ── Internal API (called by frontend-hub) ────────────────────────────────────

def _require_api_key():
    if request.headers.get("X-Governance-API-Key") != GOVERNANCE_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    return None


@app.post("/api/unmask/request")
def api_unmask_request():
    """Agent-facing endpoint: submit an unmask request from frontend-hub."""
    denied = _require_api_key()
    if denied:
        return denied

    import json as _json
    data        = request.get_json(force=True) or {}
    user_id     = (data.get("user_id")     or "").strip()
    username    = (data.get("username")    or "").strip()
    customer_id = (data.get("customer_id") or "").strip()
    fields      = data.get("fields", [])
    reason_code = (data.get("reason_code") or "").strip()
    ticket_ref  = (data.get("ticket_ref")  or "").strip()
    notes       = (data.get("notes")       or "").strip()

    if not all([user_id, username, customer_id, reason_code]):
        return jsonify({"error": "Missing required fields: user_id, username, customer_id, reason_code"}), 400
    if reason_code not in UNMASK_REASON_CODES:
        return jsonify({"error": f"Invalid reason_code. Valid: {UNMASK_REASON_CODES}"}), 400
    if not isinstance(fields, list):
        fields = []

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO unmask_sessions
               (user_id, username, customer_id, fields, reason_code, ticket_ref, notes)
               VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (user_id, username, customer_id, _json.dumps(fields), reason_code, ticket_ref, notes))
        token_id = str(cur.fetchone()[0])
    conn.commit()
    conn.close()

    log_event("unmask_requested_api",
              {"username": username, "customer_id": customer_id,
               "reason_code": reason_code, "ticket_ref": ticket_ref, "fields": fields})
    return jsonify({"token_id": token_id, "status": "pending"})


@app.get("/api/unmask/status/<token_id>")
def api_unmask_status(token_id):
    """Agent polls this to check approval status of their unmask request."""
    import json as _json
    conn = get_db()
    row  = qone(conn,
        "SELECT id, status, expires_at, fields, reason_code, username, used_at "
        "FROM unmask_sessions WHERE id=%s",
        (token_id,))
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404

    fields = row["fields"] if isinstance(row["fields"], list) else _json.loads(row["fields"] or "[]")
    return jsonify({
        "token_id":   str(row["id"]),
        "status":     row["status"],
        "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
        "fields":     fields,
        "reason_code": row["reason_code"],
        "username":   row["username"],
        "consumed":   bool(row.get("used_at")),
    })


# ── Expiry background worker ──────────────────────────────────────────────────

def _kc_revoke_role_raw(user_id, role_name):
    """Standalone revoke that gets its own admin token — safe to call from background thread."""
    token_resp = requests.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": KEYCLOAK_ADMIN_USER, "password": KEYCLOAK_ADMIN_PASS},
        timeout=5)
    token = token_resp.json()["access_token"]
    hdrs  = {"Authorization": f"Bearer {token}"}
    role_resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{role_name}",
        headers=hdrs, timeout=5)
    requests.delete(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
        f"/users/{user_id}/role-mappings/realm",
        headers=hdrs, json=[role_resp.json()], timeout=5)


def _expiry_worker():
    while True:
        time.sleep(60)
        try:
            conn = psycopg2.connect(DATABASE_URL)

            # ── 1. Time-bound role expiry ─────────────────────────────────────
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT * FROM governance_role_requests
                       WHERE status='approved' AND expires_at IS NOT NULL
                         AND expires_at <= NOW() AND revoked_at IS NULL
                         AND requested_role IS NOT NULL""")
                expired = cur.fetchall()

            for row in expired:
                try:
                    _kc_revoke_role_raw(row["user_id"], row["requested_role"])
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE governance_role_requests SET revoked_at=NOW() WHERE id=%s",
                            (row["id"],))
                    conn.commit()
                    log_event("role_expired",
                              {"username": row["username"], "role": row["requested_role"]})
                except Exception:
                    pass

            # ── 2. Access review auto-apply on due date ───────────────────────
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT * FROM governance_access_campaigns
                       WHERE status='active' AND due_date < CURRENT_DATE""")
                overdue = cur.fetchall()

            for campaign in overdue:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(
                        """SELECT * FROM governance_review_items
                           WHERE campaign_id=%s AND decision IN ('revoke','pending')""",
                        (campaign["id"],))
                    to_revoke = cur.fetchall()

                revoked_count = 0
                for item in to_revoke:
                    try:
                        _kc_revoke_role_raw(item["user_id"], item["role_name"])
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE governance_review_items SET decision='revoke', "
                                "decided_at=NOW(), decided_by='auto-apply' WHERE id=%s",
                                (item["id"],))
                        revoked_count += 1
                    except Exception:
                        pass

                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE governance_access_campaigns SET status='completed', "
                        "completed_at=NOW() WHERE id=%s",
                        (campaign["id"],))
                conn.commit()
                log_event("access_review_auto_applied",
                          {"campaign": campaign["name"], "revoked": revoked_count})

            # ── 3. Package request expiry ────────────────────────────────
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT apr.*, ap.roles as package_roles
                       FROM access_package_requests apr
                       JOIN access_packages ap ON ap.id = apr.package_id
                       WHERE apr.status='approved' AND apr.expires_at IS NOT NULL
                         AND apr.expires_at <= NOW() AND apr.revoked_at IS NULL""")
                expired_pkgs = cur.fetchall()

            for req in expired_pkgs:
                for role in (req["granted_roles"] or req["package_roles"] or []):
                    try:
                        _kc_revoke_role_raw(req["user_id"], role)
                    except Exception:
                        pass
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE access_package_requests SET revoked_at=NOW(), status='expired' WHERE id=%s",
                        (req["id"],))
                conn.commit()
                log_event("package_expired",
                          {"username": req["username"], "package": req["package_name"]})

            conn.close()
        except Exception:
            pass


# ── Access Packages ───────────────────────────────────────────────────────────

@app.get("/packages")
@login_required
def packages_list():
    view   = request.args.get("view", "catalog")
    conn   = get_db()
    pkgs   = qrows(conn, "SELECT * FROM access_packages ORDER BY name")
    reqs   = qrows(conn,
        """SELECT apr.*, ap.roles as package_roles
           FROM access_package_requests apr
           JOIN access_packages ap ON ap.id = apr.package_id
           ORDER BY apr.requested_at DESC""")
    conn.close()
    pending_reqs = [r for r in reqs if r["status"] == "pending"]
    return render_template("packages.html",
                           pkgs=pkgs, reqs=reqs, pending_reqs=pending_reqs,
                           view=view, roles=GOVERNED_ROLES)


@app.post("/packages/add")
@login_required
def packages_add():
    name    = (request.form.get("name") or "").strip()
    desc    = (request.form.get("description") or "").strip()
    roles   = request.form.getlist("roles")
    dur_str = (request.form.get("max_duration_hours") or "").strip()
    max_dur = int(dur_str) if dur_str.isdigit() and int(dur_str) > 0 else None
    req_appr = request.form.get("requires_approval") == "true"
    if not name or not roles:
        flash("Name and at least one role are required", "danger")
        return redirect(url_for("packages_list"))
    conn = get_db()
    try:
        execute(conn,
            """INSERT INTO access_packages
               (name, description, roles, max_duration_hours, requires_approval, enabled, created_by)
               VALUES (%s, %s, %s, %s, %s, true, %s)""",
            (name, desc, roles, max_dur, req_appr, ADMIN_USER))
        conn.commit()
        flash(f"Package '{name}' created", "success")
    except Exception as exc:
        conn.rollback()
        flash(f"Error: {exc}", "danger")
    finally:
        conn.close()
    return redirect(url_for("packages_list"))


@app.post("/packages/<int:pkg_id>/toggle")
@login_required
def packages_toggle(pkg_id):
    conn = get_db()
    execute(conn, "UPDATE access_packages SET enabled = NOT enabled WHERE id = %s", (pkg_id,))
    conn.commit()
    conn.close()
    flash("Package status toggled", "success")
    return redirect(url_for("packages_list"))


@app.post("/packages/<int:pkg_id>/delete")
@login_required
def packages_delete(pkg_id):
    conn = get_db()
    row = qone(conn, "SELECT name FROM access_packages WHERE id = %s", (pkg_id,))
    execute(conn, "DELETE FROM access_packages WHERE id = %s", (pkg_id,))
    conn.commit()
    conn.close()
    flash(f"Package '{row['name'] if row else pkg_id}' deleted", "success")
    return redirect(url_for("packages_list"))


@app.post("/packages/requests/<int:req_id>/approve")
@login_required
def package_request_approve(req_id):
    conn = get_db()
    req  = qone(conn,
        """SELECT apr.*, ap.roles as package_roles, ap.max_duration_hours
           FROM access_package_requests apr
           JOIN access_packages ap ON ap.id = apr.package_id
           WHERE apr.id = %s""", (req_id,))
    conn.close()
    if not req or req["status"] != "pending":
        flash("Request not found or not pending", "danger")
        return redirect(url_for("packages_list", view="requests"))

    roles_to_grant = list(req["package_roles"] or [])

    # SoD check for each role in the package
    for role in roles_to_grant:
        ok, reason = sod_check(req["user_id"], role)
        if not ok:
            flash(f"Blocked — SoD violation: {reason}", "danger")
            return redirect(url_for("packages_list", view="requests"))

    try:
        for role in roles_to_grant:
            kc_assign_role(req["user_id"], role)

        max_dur = req["max_duration_hours"]
        expires_at_sql = (
            f"NOW() + INTERVAL '{max_dur} hours'" if max_dur else "NULL"
        )
        conn = get_db()
        execute(conn,
            f"""UPDATE access_package_requests
                SET status='approved', reviewed_at=NOW(), reviewed_by=%s,
                    expires_at={expires_at_sql}, granted_roles=%s
                WHERE id=%s""",
            (ADMIN_USER, roles_to_grant, req_id))
        conn.commit()
        conn.close()
        log_event("package_approved",
                  {"username": req["username"], "package": req["package_name"],
                   "roles": roles_to_grant})
        duration_msg = (f" — access expires in {req['max_duration_hours']}h"
                        if req["max_duration_hours"] else " — permanent access")
        flash(f"Package '{req['package_name']}' approved for {req['username']}{duration_msg}", "success")
    except Exception as exc:
        flash(f"Keycloak error: {exc}", "danger")
    return redirect(url_for("packages_list", view="requests"))


@app.post("/packages/requests/<int:req_id>/reject")
@login_required
def package_request_reject(req_id):
    conn = get_db()
    row  = qone(conn, "SELECT username, package_name FROM access_package_requests WHERE id=%s", (req_id,))
    execute(conn,
        "UPDATE access_package_requests SET status='rejected', reviewed_at=NOW(), reviewed_by=%s WHERE id=%s",
        (ADMIN_USER, req_id))
    conn.commit()
    conn.close()
    if row:
        log_event("package_rejected", {"username": row["username"], "package": row["package_name"]})
    flash("Package request rejected", "warning")
    return redirect(url_for("packages_list", view="requests"))


# ── Self-service portal ───────────────────────────────────────────────────────

def portal_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("portal_user_id"):
            return redirect(url_for("portal_login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/portal/login", methods=["GET", "POST"])
def portal_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            resp = requests.post(
                f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id":  "governance-portal",
                    "username":   username,
                    "password":   password,
                },
                timeout=5,
            )
            if resp.status_code != 200:
                flash("Invalid credentials", "danger")
                return render_template("portal_login.html")

            token_data = resp.json()
            # Decode sub (user_id) from token without verifying signature (internal trust)
            import base64, json as _json
            payload = token_data["access_token"].split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = _json.loads(base64.urlsafe_b64decode(payload))

            session["portal_user_id"] = claims["sub"]
            session["portal_username"] = claims.get("preferred_username", username)
            session["portal_email"]    = claims.get("email", "")
            return redirect(url_for("portal_dashboard"))
        except Exception as e:
            flash(f"Login error: {e}", "danger")
    return render_template("portal_login.html")


@app.get("/portal/logout")
def portal_logout():
    session.pop("portal_user_id", None)
    session.pop("portal_username", None)
    session.pop("portal_email", None)
    return redirect(url_for("portal_login"))


@app.get("/portal")
@portal_login_required
def portal_dashboard():
    user_id  = session["portal_user_id"]
    username = session["portal_username"]
    try:
        my_roles = kc_get_user_roles(user_id)
    except Exception:
        my_roles = []
    conn = get_db()
    my_requests = qrows(conn,
        "SELECT * FROM governance_role_requests WHERE user_id=%s ORDER BY requested_at DESC LIMIT 10",
        (user_id,))
    packages = qrows(conn, "SELECT * FROM access_packages WHERE enabled=true ORDER BY name")
    my_pkg_requests = qrows(conn,
        "SELECT * FROM access_package_requests WHERE user_id=%s ORDER BY requested_at DESC LIMIT 10",
        (user_id,))
    conn.close()
    return render_template("portal_dashboard.html",
                           username=username, my_roles=my_roles,
                           my_requests=my_requests, roles=GOVERNED_ROLES,
                           packages=packages, my_pkg_requests=my_pkg_requests)


@app.post("/portal/request")
@portal_login_required
def portal_request():
    user_id  = session["portal_user_id"]
    username = session["portal_username"]
    email    = session["portal_email"]
    requested_role = request.form.get("requested_role") or None
    old_role       = request.form.get("old_role") or None
    expires_at     = request.form.get("expires_at") or None
    notes          = request.form.get("notes", "")
    req_type       = "onboarding" if not old_role else "change"

    conn = get_db()
    execute(conn,
        """INSERT INTO governance_role_requests
           (user_id, username, email, request_type, requested_role, old_role, expires_at, notes)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (user_id, username, email, req_type, requested_role, old_role, expires_at, notes))
    conn.commit()
    conn.close()
    log_event("portal_role_request", {"username": username, "requested_role": requested_role})
    flash("Request submitted — an admin will review it shortly", "success")
    return redirect(url_for("portal_dashboard"))


@app.post("/portal/package-request")
@portal_login_required
def portal_package_request():
    user_id       = session["portal_user_id"]
    username      = session["portal_username"]
    email         = session.get("portal_email", "")
    package_id    = request.form.get("package_id", "")
    justification = (request.form.get("justification") or "").strip()

    if not package_id:
        flash("Package is required", "danger")
        return redirect(url_for("portal_dashboard"))

    conn = get_db()
    pkg = qone(conn, "SELECT * FROM access_packages WHERE id=%s AND enabled=true", (package_id,))
    if not pkg:
        conn.close()
        flash("Package not found or disabled", "danger")
        return redirect(url_for("portal_dashboard"))

    # Check no pending/approved request already exists for this package
    existing = qone(conn,
        "SELECT id FROM access_package_requests WHERE user_id=%s AND package_id=%s AND status IN ('pending','approved')",
        (user_id, package_id))
    if existing:
        conn.close()
        flash(f"You already have a pending or active '{pkg['name']}' request", "warning")
        return redirect(url_for("portal_dashboard"))

    execute(conn,
        """INSERT INTO access_package_requests
           (package_id, package_name, user_id, username, email, justification)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (package_id, pkg["name"], user_id, username, email, justification))
    conn.commit()
    conn.close()
    log_event("portal_package_request",
              {"username": username, "package": pkg["name"]})
    flash(f"Access package '{pkg['name']}' requested — pending admin approval", "success")
    return redirect(url_for("portal_dashboard"))


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    for i in range(10):
        try:
            init_db()
            print("Governance DB initialised ✓")
            break
        except Exception as exc:
            wait = 2 ** i
            print(f"DB not ready ({exc}), retry in {wait}s…")
            time.sleep(wait)
    threading.Thread(target=_expiry_worker, daemon=True).start()
    app.run(host="0.0.0.0", port=8889, debug=False)
