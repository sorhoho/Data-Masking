import os
import sqlite3
import time
import requests
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "admin-secret-key")

OPA_URL    = os.environ.get("OPA_URL",          "http://opa:8181")
ADMIN_USER = os.environ.get("ADMIN_USER",       "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASSWORD",   "admin123")
DB_PATH    = os.environ.get("DB_PATH",          "/data/admin.db")

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
ROLES = ["agent", "supervisor", "vip_agent", "admin", "partner"]

_DEFAULT_MASKS = [
    ("agent", "name"), ("agent", "msisdn"), ("agent", "email"),
    ("agent", "national_id"), ("agent", "address"),
    ("agent", "last_call_duration"), ("agent", "data_roaming_gb"),
    ("agent", "last_location"),
    ("supervisor", "msisdn"), ("supervisor", "national_id"),
    # partner: full L1+L2 masking (machine-to-machine external access)
    ("partner", "name"), ("partner", "msisdn"), ("partner", "email"),
    ("partner", "national_id"), ("partner", "address"),
    ("partner", "last_call_duration"), ("partner", "data_roaming_gb"),
    ("partner", "last_location"),
]
_DEFAULT_VIPS = [
    ("C001", "Initial VIP – seeded on first run"),
    ("C004", "Initial VIP – seeded on first run"),
]

# Backend registry — seeded on first run
_DEFAULT_BACKENDS = [
    ("crm",     "CRM System",      "http://crm-mock:5000",     "Main CRM — field names are canonical"),
    ("billing", "Billing System",  "http://billing-mock:5001", "Billing backend — aliased field names"),
]

# Per-backend field mappings: (backend_id, backend_field, canonical_field, classification)
_DEFAULT_FIELD_MAPPINGS = [
    # CRM fields match canonical names
    ("crm", "name",               "name",               "L1"),
    ("crm", "msisdn",             "msisdn",             "L1"),
    ("crm", "email",              "email",              "L1"),
    ("crm", "national_id",        "national_id",        "L1"),
    ("crm", "address",            "address",            "L1"),
    ("crm", "last_call_duration", "last_call_duration", "L2"),
    ("crm", "data_roaming_gb",    "data_roaming_gb",    "L2"),
    ("crm", "last_location",      "last_location",      "L2"),
    # Billing fields with different names
    ("billing", "mobilenum",        "msisdn",             "L1"),
    ("billing", "subname",          "name",               "L1"),
    ("billing", "ic_num",           "national_id",        "L1"),
    ("billing", "billing_address",  "address",            "L1"),
    ("billing", "call_duration_s",  "last_call_duration", "L2"),
    ("billing", "roaming_gb",       "data_roaming_gb",    "L2"),
]


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS vip_customers (
            customer_id TEXT PRIMARY KEY,
            added_by    TEXT DEFAULT 'system',
            added_at    TEXT NOT NULL,
            notes       TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS role_field_masks (
            role  TEXT NOT NULL,
            field TEXT NOT NULL,
            PRIMARY KEY (role, field)
        );
        CREATE TABLE IF NOT EXISTS sync_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            synced_at TEXT NOT NULL,
            status    TEXT NOT NULL,
            message   TEXT
        );
        CREATE TABLE IF NOT EXISTS backends (
            backend_id   TEXT PRIMARY KEY,
            backend_name TEXT NOT NULL,
            base_url     TEXT DEFAULT '',
            description  TEXT DEFAULT '',
            created_at   TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS field_mappings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            backend_id     TEXT NOT NULL REFERENCES backends(backend_id) ON DELETE CASCADE,
            backend_field  TEXT NOT NULL,
            canonical_field TEXT NOT NULL,
            classification TEXT NOT NULL DEFAULT 'L1',
            UNIQUE(backend_id, backend_field)
        );
    """)
    now = datetime.utcnow().isoformat()
    if not conn.execute("SELECT 1 FROM vip_customers LIMIT 1").fetchone():
        conn.executemany(
            "INSERT INTO vip_customers (customer_id, added_by, added_at, notes) "
            "VALUES (?, 'system', ?, ?)",
            [(cid, now, note) for cid, note in _DEFAULT_VIPS],
        )
    if not conn.execute("SELECT 1 FROM role_field_masks LIMIT 1").fetchone():
        conn.executemany(
            "INSERT INTO role_field_masks (role, field) VALUES (?, ?)",
            _DEFAULT_MASKS,
        )
    if not conn.execute("SELECT 1 FROM backends LIMIT 1").fetchone():
        conn.executemany(
            "INSERT INTO backends (backend_id, backend_name, base_url, description, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            [(bid, name, url, desc, now) for bid, name, url, desc in _DEFAULT_BACKENDS],
        )
    if not conn.execute("SELECT 1 FROM field_mappings LIMIT 1").fetchone():
        conn.executemany(
            "INSERT INTO field_mappings (backend_id, backend_field, canonical_field, classification) "
            "VALUES (?, ?, ?, ?)",
            _DEFAULT_FIELD_MAPPINGS,
        )
    conn.commit()
    conn.close()


# ── Config assembly + OPA sync ────────────────────────────────────────────────

def get_config():
    conn = get_db()
    vip_rows     = conn.execute("SELECT customer_id FROM vip_customers").fetchall()
    mask_rows    = conn.execute("SELECT role, field FROM role_field_masks").fetchall()
    mapping_rows = conn.execute(
        "SELECT backend_id, backend_field, canonical_field, classification "
        "FROM field_mappings ORDER BY backend_id, backend_field"
    ).fetchall()
    conn.close()

    vip_customers = {row["customer_id"]: True for row in vip_rows}

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
            "canonical":       row["canonical_field"],
            "classification":  row["classification"],
        }

    return {
        "vip_customers":      vip_customers,
        "role_masked_fields": role_masked_fields,
        "backends":           backends,
    }


def sync_to_opa(retries=3):
    config  = get_config()
    status  = "error"
    message = "no attempt"
    for attempt in range(retries):
        try:
            resp = requests.put(
                f"{OPA_URL}/v1/data/masking_config",
                json=config, timeout=5,
            )
            if resp.status_code in (200, 204):
                status  = "ok"
                message = f"HTTP {resp.status_code}"
                break
            message = f"HTTP {resp.status_code}"
        except Exception as exc:
            message = str(exc)
            if attempt < retries - 1:
                time.sleep(2 ** attempt)

    conn = get_db()
    conn.execute(
        "INSERT INTO sync_log (synced_at, status, message) VALUES (?, ?, ?)",
        (datetime.utcnow().isoformat(), status, message),
    )
    conn.commit()
    conn.close()
    return status == "ok", message


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
    recent_syncs  = conn.execute(
        "SELECT * FROM sync_log ORDER BY id DESC LIMIT 5"
    ).fetchall()
    backend_count = conn.execute("SELECT COUNT(*) FROM backends").fetchone()[0]
    mapping_count = conn.execute("SELECT COUNT(*) FROM field_mappings").fetchone()[0]
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
    return jsonify({"status": "ok"})


# ── VIP management ────────────────────────────────────────────────────────────

@app.get("/vip")
@login_required
def vip_list():
    conn = get_db()
    customers = conn.execute(
        "SELECT * FROM vip_customers ORDER BY added_at DESC"
    ).fetchall()
    conn.close()
    return render_template("vip.html", customers=customers)


@app.post("/vip/add")
@login_required
def vip_add():
    cid   = (request.form.get("customer_id") or "").strip().upper()
    notes = (request.form.get("notes") or "").strip()
    if not cid:
        flash("Customer ID is required", "danger")
        return redirect(url_for("vip_list"))
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO vip_customers (customer_id, added_by, added_at, notes) "
            "VALUES (?, ?, ?, ?)",
            (cid, ADMIN_USER, datetime.utcnow().isoformat(), notes),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(
            f"Added {cid} as VIP " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
            "success" if ok else "warning",
        )
    except sqlite3.IntegrityError:
        flash(f"'{cid}' is already a VIP customer", "warning")
    finally:
        conn.close()
    return redirect(url_for("vip_list"))


@app.post("/vip/remove/<customer_id>")
@login_required
def vip_remove(customer_id):
    conn = get_db()
    conn.execute("DELETE FROM vip_customers WHERE customer_id = ?", (customer_id,))
    conn.commit()
    conn.close()
    ok, msg = sync_to_opa()
    flash(
        f"Removed {customer_id} from VIP " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
        "success" if ok else "warning",
    )
    return redirect(url_for("vip_list"))


# ── Masking rules (role × field matrix) ──────────────────────────────────────

@app.get("/roles")
@login_required
def roles_view():
    conn = get_db()
    mask_rows = conn.execute("SELECT role, field FROM role_field_masks").fetchall()
    conn.close()
    masked = {role: {f: False for f, _ in FIELDS} for role in ROLES}
    for row in mask_rows:
        if row["role"] in masked and row["field"] in masked[row["role"]]:
            masked[row["role"]][row["field"]] = True
    return render_template("roles.html", roles=ROLES, fields=FIELDS, masked=masked)


@app.post("/roles/save")
@login_required
def roles_save():
    conn = get_db()
    conn.execute("DELETE FROM role_field_masks")
    inserts = [
        (role, field)
        for role in ROLES
        for field, _ in FIELDS
        if request.form.get(f"{role}__{field}")
    ]
    if inserts:
        conn.executemany(
            "INSERT INTO role_field_masks (role, field) VALUES (?, ?)", inserts
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
    conn = get_db()
    backends = conn.execute(
        "SELECT * FROM backends ORDER BY backend_id"
    ).fetchall()
    mappings = conn.execute(
        "SELECT * FROM field_mappings ORDER BY backend_id, backend_field"
    ).fetchall()
    conn.close()
    # Group mappings by backend_id
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
    bid   = (request.form.get("backend_id")   or "").strip().lower()
    name  = (request.form.get("backend_name") or "").strip()
    url   = (request.form.get("base_url")     or "").strip()
    desc  = (request.form.get("description")  or "").strip()
    if not bid or not name:
        flash("Backend ID and name are required", "danger")
        return redirect(url_for("backends_list"))
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO backends (backend_id, backend_name, base_url, description, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (bid, name, url, desc, datetime.utcnow().isoformat()),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(f"Backend '{bid}' added " + ("– synced to OPA ✓" if ok else f"– OPA sync failed: {msg}"),
              "success" if ok else "warning")
    except sqlite3.IntegrityError:
        flash(f"Backend ID '{bid}' already exists", "warning")
    finally:
        conn.close()
    return redirect(url_for("backends_list"))


@app.post("/backends/<backend_id>/delete")
@login_required
def backend_delete(backend_id):
    conn = get_db()
    conn.execute("DELETE FROM backends WHERE backend_id = ?", (backend_id,))
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
        conn.execute(
            "INSERT INTO field_mappings (backend_id, backend_field, canonical_field, classification) "
            "VALUES (?, ?, ?, ?)",
            (backend_id, bfield, canon, cls),
        )
        conn.commit()
        ok, msg = sync_to_opa()
        flash(f"Mapping {bfield}→{canon} added " + ("– synced ✓" if ok else f"– sync failed: {msg}"),
              "success" if ok else "warning")
    except sqlite3.IntegrityError:
        flash(f"Field '{bfield}' already mapped for backend '{backend_id}'", "warning")
    finally:
        conn.close()
    return redirect(url_for("backends_list"))


@app.post("/backends/<backend_id>/fields/<int:field_id>/delete")
@login_required
def field_mapping_delete(backend_id, field_id):
    conn = get_db()
    conn.execute("DELETE FROM field_mappings WHERE id = ? AND backend_id = ?",
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
    flash(f"OPA sync {'succeeded ✓' if ok else 'failed: ' + msg}",
          "success" if ok else "danger")
    return redirect(url_for("dashboard"))


@app.get("/api/config")
@login_required
def api_config():
    return jsonify(get_config())


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("Waiting for OPA and pushing initial config…")
    for i in range(6):
        ok, msg = sync_to_opa(retries=1)
        if ok:
            print(f"OPA sync OK: {msg}")
            break
        print(f"OPA not ready ({msg}), retry in {2**i}s…")
        time.sleep(2 ** i)
    app.run(host="0.0.0.0", port=8888, debug=False)
