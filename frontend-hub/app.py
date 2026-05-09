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

KONG_URL = os.environ.get("KONG_URL", "http://kong:8000")
REALM    = "demo"

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
    token        = _oa(app_key).authorize_access_token()
    access_token = token["access_token"]
    ui_resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=8,
    )
    userinfo = ui_resp.json() if ui_resp.ok else {}
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
                           result=None, error=None)


@app.get("/<app_key>/lookup")
def app_lookup(app_key):
    if app_key not in APPS:
        return "Unknown app", 404
    if not app_token(app_key):
        return redirect(url_for("app_login", app_key=app_key))

    cid        = request.args.get("customer_id", "").strip()
    msisdn     = request.args.get("msisdn", "").strip()
    access_ref = request.args.get("ref", "").strip()
    endpoint   = request.args.get("endpoint", "crm")  # crm | billing

    if not cid and not msisdn:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Customer ID or MSISDN required")

    headers = {"Authorization": f"Bearer {app_token(app_key)}"}
    if access_ref:
        headers["X-Access-Reference"] = access_ref

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
                               access_ref=access_ref)

    except requests.exceptions.ConnectionError:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Cannot reach Kong API Gateway")
    except requests.exceptions.Timeout:
        return render_template("app.html",
                               app_key=app_key, app_cfg=APPS[app_key],
                               user=app_user(app_key),
                               result=None, error="Request timed out")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3001, debug=False)
