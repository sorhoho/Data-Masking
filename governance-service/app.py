import os
import threading
import time
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

GOVERNED_ROLES = ["agent", "supervisor", "vip_agent", "admin", "partner"]


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
    ]
    for stmt in stmts:
        execute(conn, stmt)
    conn.commit()
    conn.close()


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


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_event(event_type, details):
    try:
        requests.post(LOG_DASHBOARD_URL, json={
            "service":   "governance-service",
            "event":     event_type,
            "details":   details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, timeout=2)
    except Exception:
        pass


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
    recent         = qrows(conn, "SELECT * FROM governance_role_requests ORDER BY requested_at DESC LIMIT 8")
    conn.close()
    return render_template("dashboard.html", pending=pending,
                           active_reviews=active_reviews, recent=recent)


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


# ── Users & Offboarding ───────────────────────────────────────────────────────

@app.get("/users")
@login_required
def users_list():
    try:
        users = kc_get_users()
        for u in users:
            u["governed_roles"] = kc_get_user_roles(u["id"])
    except Exception as e:
        users = []
        flash(f"Keycloak unavailable: {e}", "danger")
    return render_template("users.html", users=users, roles=GOVERNED_ROLES)


@app.post("/users/<user_id>/offboard")
@login_required
def offboard_user(user_id):
    username = request.form.get("username", user_id)
    notes    = request.form.get("notes", "Admin-initiated offboarding")
    conn = get_db()
    execute(conn,
        """INSERT INTO governance_role_requests
           (user_id, username, request_type, notes)
           VALUES (%s,%s,'offboarding',%s)""",
        (user_id, username, notes))
    conn.commit()
    conn.close()
    flash(f"Offboarding request created for {username} — approve it to revoke all roles", "warning")
    return redirect(url_for("requests_list"))


@app.post("/users/<user_id>/request-change")
@login_required
def request_role_change(user_id):
    username     = request.form.get("username", user_id)
    email        = request.form.get("email", "")
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
    log_event("role_request_submitted",
              {"username": username, "type": req_type, "requested_role": new_role})
    flash(f"Role change request submitted for {username}", "success")
    return redirect(url_for("requests_list"))


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


# ── Expiry background worker ──────────────────────────────────────────────────

def _expiry_worker():
    while True:
        time.sleep(60)
        try:
            conn = psycopg2.connect(DATABASE_URL)
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """SELECT * FROM governance_role_requests
                       WHERE status='approved' AND expires_at IS NOT NULL
                         AND expires_at <= NOW() AND revoked_at IS NULL
                         AND requested_role IS NOT NULL""")
                expired = cur.fetchall()

            for row in expired:
                try:
                    # Get fresh token per revocation to avoid expiry
                    token_resp = requests.post(
                        f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token",
                        data={"grant_type": "password", "client_id": "admin-cli",
                              "username": KEYCLOAK_ADMIN_USER, "password": KEYCLOAK_ADMIN_PASS},
                        timeout=5)
                    token = token_resp.json()["access_token"]
                    hdrs  = {"Authorization": f"Bearer {token}"}

                    role_resp = requests.get(
                        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/roles/{row['requested_role']}",
                        headers=hdrs, timeout=5)
                    requests.delete(
                        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}"
                        f"/users/{row['user_id']}/role-mappings/realm",
                        headers=hdrs, json=[role_resp.json()], timeout=5)

                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE governance_role_requests SET revoked_at=NOW() WHERE id=%s",
                            (row["id"],))
                    conn.commit()
                    log_event("role_expired",
                              {"username": row["username"], "role": row["requested_role"]})
                except Exception:
                    pass
            conn.close()
        except Exception:
            pass


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
