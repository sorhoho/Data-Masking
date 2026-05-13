import os
import requests
from functools import wraps
from flask import Flask, session, redirect, url_for, render_template, request, jsonify
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "hub-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

_kc_host = os.environ.get("KEYCLOAK_HOST", "")
if _kc_host:
    KEYCLOAK_URL          = f"https://{_kc_host}"
    KEYCLOAK_INTERNAL_URL = f"https://{_kc_host}"
else:
    KEYCLOAK_URL          = os.environ.get("KEYCLOAK_URL",          "http://localhost:8080")
    KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")

KONG_URL                = os.environ.get("KONG_URL",                "http://kong:8000")
OPA_URL                 = os.environ.get("OPA_URL",                 "http://opa:8181")
GOVERNANCE_INTERNAL_URL = os.environ.get("GOVERNANCE_INTERNAL_URL", "http://governance-service:8889")
GOVERNANCE_API_KEY      = os.environ.get("GOVERNANCE_API_KEY",      "governance-internal-key")
REALM = "demo"

UNMASK_REASON_CODES = [
    "FRAUD_INVESTIGATION", "COMPLIANCE_AUDIT", "LEGAL_HOLD",
    "CUSTOMER_DISPUTE", "TECHNICAL_ESCALATION", "REGULATOR_REQUEST",
]

UNMASK_FIELDS = [
    "name", "msisdn", "email", "national_id", "address",
    "last_call_duration", "data_roaming_gb", "last_location",
]

# Same priority table as Kong — used to pick effective role from JWT claims
ROLE_PRIORITY = {
    "admin": 10, "data_admin": 9,
    "compliance_officer": 8, "fraud_analyst": 8,
    "vip_agent": 7, "vip_care": 7,
    "supervisor": 6, "care_supervisor": 6,
    "care_l2": 5, "billing_agent": 5, "roaming_ops": 5,
    "care_l1": 4, "noc_operator": 4, "field_technician": 4, "audit_viewer": 4,
    "agent": 3,
    "partner": 2, "b2b_partner": 2, "mvno_partner": 2,
}

def pick_role(roles):
    best, best_p = None, -1
    for r in (roles or []):
        p = ROLE_PRIORITY.get(r, -1)
        if p > best_p:
            best, best_p = r, p
    return best

# ── App registry ──────────────────────────────────────────────────────────────
# client_id must match Keycloak client AND the App ID registered in admin-service
APPS = {
    "agent": {
        "client_id":   "agent-portal",
        "secret":      "agent-portal-secret",
        "label":       "Agent Portal",
        "description": "Front-line care, billing & field operations",
        "color":       "primary",
        "icon":        "&#127911;",
    },
    "supervisor": {
        "client_id":   "supervisor-dashboard",
        "secret":      "supervisor-dashboard-secret",
        "label":       "Supervisor Dashboard",
        "description": "Team leads, supervisors & VIP operations",
        "color":       "success",
        "icon":        "&#128084;",
    },
    "fraud": {
        "client_id":   "fraud-console",
        "secret":      "fraud-console-secret",
        "label":       "Fraud Console",
        "description": "Fraud analysts & compliance officers",
        "color":       "danger",
        "icon":        "&#128270;",
    },
    "audit": {
        "client_id":   "audit-viewer-app",
        "secret":      "audit-viewer-app-secret",
        "label":       "Audit Viewer",
        "description": "Read-only compliance & audit access",
        "color":       "warning",
        "icon":        "&#128203;",
    },
    "partner": {
        "client_id":   "partner-api",
        "secret":      "partner-api-secret",
        "label":       "Partner API",
        "description": "B2B & MVNO external partner access",
        "color":       "secondary",
        "icon":        "&#129309;",
    },
}

# ── Register one OAuth client per app ─────────────────────────────────────────
oauth = OAuth(app)
for _key, _cfg in APPS.items():
    oauth.register(
        name=f"kc_{_key}",
        client_id=_cfg["client_id"],
        client_secret=_cfg["secret"],
        authorize_url=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth",
        access_token_url=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/token",
        userinfo_endpoint=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
        jwks_uri=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/certs",
        client_kwargs={
            "scope": "openid profile email roles",
            "token_endpoint_auth_method": "client_secret_post",
        },
    )


def _oa(app_key):
    return oauth.create_client(f"kc_{app_key}")


def app_user(app_key):
    return session.get(f"{app_key}_user")


def app_token(app_key):
    return session.get(f"{app_key}_token")


def login_required_for(app_key):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not app_token(app_key):
                return redirect(url_for("app_login", app_key=app_key))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ── Portal ────────────────────────────────────────────────────────────────────

@app.get("/")
def portal():
    logged_in = {k: bool(app_token(k)) for k in APPS}
    return render_template("portal.html", apps=APPS, logged_in=logged_in)


# ── Per-app auth ──────────────────────────────────────────────────────────────

@app.get("/<app_key>/login")
def app_login(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    redirect_uri = url_for("app_callback", app_key=app_key, _external=True)
    return _oa(app_key).authorize_redirect(redirect_uri)


@app.get("/<app_key>/callback")
def app_callback(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    oa = _oa(app_key)
    try:
        token = oa.authorize_access_token()
    except Exception:
        # parse_id_token may fail (nonce/at_hash mismatch, key issues).
        # fetch_access_token already ran and stored the token in g before
        # the ID-token validation step — retrieve it from there.
        token = oa.token or {}
        if not token or "access_token" not in token:
            return redirect(url_for("app_login", app_key=app_key))
    access_token = token["access_token"]
    ui_resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=8,
    )
    userinfo  = ui_resp.json() if ui_resp.ok else {}
    user_role = pick_role(userinfo.get("roles", []))

    # ── App-role gate: check OPA bundle before granting session ──────────────
    app_id          = APPS[app_key]["client_id"]
    allowed_roles   = None   # None = app not in registry → open
    opa_check_error = None
    try:
        opa_resp = requests.get(
            f"{OPA_URL}/v1/data/masking_config/app_roles",
            timeout=3,
        )
        if opa_resp.ok:
            app_roles_map = opa_resp.json().get("result", {})
            if app_id in app_roles_map:
                allowed_roles = app_roles_map[app_id]
    except Exception as exc:
        opa_check_error = str(exc)   # OPA down → fail open, log only

    if allowed_roles is not None and user_role not in allowed_roles:
        return render_template("denied.html",
                               app_key=app_key,
                               app_cfg=APPS[app_key],
                               username=userinfo.get("preferred_username", "unknown"),
                               user_role=user_role,
                               allowed_roles=sorted(allowed_roles))

    session[f"{app_key}_token"]    = access_token
    session[f"{app_key}_id_token"] = token.get("id_token", "")
    session[f"{app_key}_user"]     = userinfo
    return redirect(url_for("app_home", app_key=app_key))


@app.get("/<app_key>/logout")
def app_logout(app_key):
    id_token = session.pop(f"{app_key}_id_token", "")
    session.pop(f"{app_key}_token", None)
    session.pop(f"{app_key}_user", None)
    logout_url = (
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
        f"?post_logout_redirect_uri={url_for('portal', _external=True)}"
        f"&id_token_hint={id_token}"
    )
    return redirect(logout_url)


# ── Per-app pages ─────────────────────────────────────────────────────────────

@app.get("/<app_key>/")
def app_home(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    if not app_token(app_key):
        return redirect(url_for("app_login", app_key=app_key))
    return render_template("app.html",
                           app_key=app_key,
                           app_cfg=APPS[app_key],
                           user=app_user(app_key),
                           result=None, error=None,
                           reason_codes=UNMASK_REASON_CODES,
                           unmask_fields=UNMASK_FIELDS)


@app.get("/<app_key>/lookup")
def app_lookup(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    if not app_token(app_key):
        return redirect(url_for("app_login", app_key=app_key))

    cid          = request.args.get("customer_id", "").strip()
    msisdn       = request.args.get("msisdn", "").strip()
    access_ref   = request.args.get("ref", "").strip()
    unmask_token = request.args.get("unmask_token", "").strip()
    endpoint     = request.args.get("endpoint", "crm")  # crm | billing

    if not cid and not msisdn:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Customer ID or MSISDN required",
                               reason_codes=UNMASK_REASON_CODES,
                               unmask_fields=UNMASK_FIELDS)

    headers = {"Authorization": f"Bearer {app_token(app_key)}"}
    if access_ref:
        headers["X-Access-Reference"] = access_ref
    if unmask_token:
        headers["X-Unmask-Token"] = unmask_token

    try:
        if endpoint == "billing":
            resp = requests.get(f"{KONG_URL}/api/billing/subscriber",
                                params={"msisdn": msisdn or cid},
                                headers=headers, timeout=15)
        elif cid:
            resp = requests.get(f"{KONG_URL}/api/customer/{cid}",
                                headers=headers, timeout=15)
        else:
            resp = requests.get(f"{KONG_URL}/api/customer",
                                params={"msisdn": msisdn},
                                headers=headers, timeout=15)

        result = resp.json() if resp.content else {}
        error  = None if resp.status_code == 200 else result.get("message", f"HTTP {resp.status_code}")
        if resp.status_code == 200:
            error = None
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=result if resp.status_code == 200 else None,
                               error=error,
                               raw=result,
                               http_status=resp.status_code,
                               cid=cid, msisdn=msisdn, endpoint=endpoint,
                               access_ref=access_ref, unmask_token=unmask_token,
                               reason_codes=UNMASK_REASON_CODES,
                               unmask_fields=UNMASK_FIELDS)

    except requests.exceptions.ConnectionError:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Cannot reach Kong API Gateway",
                               reason_codes=UNMASK_REASON_CODES,
                               unmask_fields=UNMASK_FIELDS)
    except requests.exceptions.Timeout:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Request timed out",
                               reason_codes=UNMASK_REASON_CODES,
                               unmask_fields=UNMASK_FIELDS)


# ── Unmask request / status ───────────────────────────────────────────────────

@app.post("/<app_key>/unmask/request")
def app_unmask_request(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    if not app_token(app_key):
        return redirect(url_for("app_login", app_key=app_key))

    user        = app_user(app_key)
    user_id     = user.get("sub", "")
    username    = user.get("preferred_username", "unknown")
    customer_id = request.form.get("customer_id", "").strip()
    fields      = request.form.getlist("fields")
    reason_code = request.form.get("reason_code", "").strip()
    ticket_ref  = request.form.get("ticket_ref", "").strip()
    notes       = request.form.get("notes", "").strip()

    error = None
    unmask_pending = None
    unmask_customer_id = customer_id

    try:
        resp = requests.post(
            f"{GOVERNANCE_INTERNAL_URL}/api/unmask/request",
            headers={"X-Governance-API-Key": GOVERNANCE_API_KEY},
            json={"user_id": user_id, "username": username,
                  "customer_id": customer_id, "fields": fields,
                  "reason_code": reason_code, "ticket_ref": ticket_ref,
                  "notes": notes},
            timeout=5,
        )
        if resp.ok:
            unmask_pending = resp.json().get("token_id")
        else:
            error = f"Unmask request failed: {resp.json().get('error', resp.text)}"
    except Exception as exc:
        error = f"Cannot reach governance service: {exc}"

    return render_template("app.html",
                           app_key=app_key, app_cfg=APPS[app_key],
                           user=app_user(app_key),
                           result=None, error=error,
                           unmask_pending=unmask_pending,
                           unmask_customer_id=unmask_customer_id,
                           reason_codes=UNMASK_REASON_CODES,
                           unmask_fields=UNMASK_FIELDS)


@app.get("/<app_key>/unmask/status/<token_id>")
def app_unmask_status(app_key, token_id):
    if app_key not in APPS:
        return jsonify({"error": "Unknown app"}), 404
    if not app_token(app_key):
        return jsonify({"error": "not authenticated"}), 401
    try:
        resp = requests.get(
            f"{GOVERNANCE_INTERNAL_URL}/api/unmask/status/{token_id}",
            timeout=5,
        )
        return jsonify(resp.json()), resp.status_code
    except Exception as exc:
        return jsonify({"error": str(exc)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3001, debug=False)
