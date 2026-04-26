import os
import threading
import requests
from functools import wraps
from flask import Flask, session, redirect, url_for, render_template, request, jsonify
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

# Trust one layer of reverse-proxy headers (needed on Render / behind nginx).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ── URL resolution ────────────────────────────────────────────────────────────
# On Render KEYCLOAK_HOST is injected via fromService; locally fall back to the
# two separate env vars so browser→Keycloak and server→Keycloak use the right URLs.
_kc_host = os.environ.get("KEYCLOAK_HOST", "")
if _kc_host:
    KEYCLOAK_URL          = f"https://{_kc_host}"
    KEYCLOAK_INTERNAL_URL = f"https://{_kc_host}"
else:
    KEYCLOAK_URL          = os.environ.get("KEYCLOAK_URL",          "http://localhost:8080")
    KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")

KONG_URL          = os.environ.get("KONG_URL",          "http://kong:8000")
LOG_DASHBOARD_URL = os.environ.get("LOG_DASHBOARD_URL", "http://log-dashboard:9000/log")
REALM             = "demo"

# ── Logging helper ────────────────────────────────────────────────────────────
def _fire(entry):
    try:
        requests.post(LOG_DASHBOARD_URL, json=entry, timeout=0.5)
    except Exception:
        pass

def log_event(level, event, **kw):
    """Fire-and-forget – never blocks the request."""
    entry = {"service": "website", "level": level, "event": event, **kw}
    threading.Thread(target=_fire, args=(entry,), daemon=True).start()


# ── Keycloak OIDC client ──────────────────────────────────────────────────────
oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id="website-client",
    client_secret="website-secret-123",
    authorize_url=f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth",
    access_token_url=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/token",
    userinfo_endpoint=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
    jwks_uri=f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/certs",
    client_kwargs={
        "scope": "openid profile email",
        "token_endpoint_auth_method": "client_secret_post",
    },
)


def current_user():
    return session.get("user")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("access_token"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return render_template("index.html", user=current_user())


@app.get("/login")
def login():
    redirect_uri = url_for("auth_callback", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)


@app.get("/auth/callback")
def auth_callback():
    token        = oauth.keycloak.authorize_access_token()
    access_token = token["access_token"]

    ui_resp  = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=8,
    )
    userinfo = ui_resp.json() if ui_resp.ok else {}

    session["user"]         = userinfo
    session["access_token"] = access_token

    log_event("info", "user_login",
              user=userinfo.get("preferred_username"),
              roles=userinfo.get("roles", []))
    return redirect(url_for("search"))


@app.get("/logout")
def logout():
    user = current_user() or {}
    log_event("info", "user_logout", user=user.get("preferred_username"))
    session.clear()
    logout_url = (
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
        f"?redirect_uri={url_for('index', _external=True)}"
    )
    return redirect(logout_url)


# ── Application routes ────────────────────────────────────────────────────────

@app.get("/search")
@login_required
def search():
    return render_template("search.html", user=current_user())


@app.get("/customer/<customer_id>")
@login_required
def customer_detail(customer_id):
    user         = current_user() or {}
    username     = user.get("preferred_username", "unknown")
    access_token = session["access_token"]

    log_event("info", "crm_request", user=username, customer_id=customer_id)

    try:
        resp = requests.get(
            f"{KONG_URL}/api/customer/{customer_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            data    = resp.json()
            masking = data.get("_masking", {})
            log_event("info", "crm_response",
                      user=username,
                      customer_id=customer_id,
                      http_status=200,
                      masked_fields=masking.get("masked_fields", []))
            return render_template("customer.html",
                                   customer=data, error=None,
                                   user=current_user(), customer_id=customer_id)

        if resp.status_code in (401, 403):
            err_body = resp.json() if resp.content else {}
            error    = err_body.get("message", f"HTTP {resp.status_code}: Access denied")
            log_event("warn", "crm_denied",
                      user=username, customer_id=customer_id,
                      http_status=resp.status_code, error=error)
        elif resp.status_code == 404:
            error = f"Customer '{customer_id}' not found in CRM"
        else:
            error = f"Upstream error – HTTP {resp.status_code}"

    except requests.exceptions.ConnectionError:
        error = "Cannot reach Kong API Gateway. Is it running?"
        log_event("error", "kong_unreachable", user=username, customer_id=customer_id)
    except requests.exceptions.Timeout:
        error = "Request timed out."
        log_event("error", "kong_timeout", user=username, customer_id=customer_id)

    return render_template("customer.html",
                           customer=None, error=error,
                           user=current_user(), customer_id=customer_id)


@app.post("/customer/<customer_id>/reveal")
@login_required
def reveal_customer(customer_id):
    user         = current_user() or {}
    username     = user.get("preferred_username", "unknown")
    access_token = session["access_token"]
    reason       = (request.form.get("reason") or "").strip()

    if not reason:
        return jsonify({"error": "Reason is required"}), 400

    log_event("warn", "unmask_request",
              user=username, customer_id=customer_id, unmask_reason=reason)

    try:
        resp = requests.get(
            f"{KONG_URL}/api/unmask/{customer_id}",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Unmask-Reason": reason,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            log_event("warn", "unmask_success",
                      user=username, customer_id=customer_id, unmask_reason=reason)
            return jsonify(resp.json())

        err_body = resp.json() if resp.content else {}
        err_msg  = err_body.get("message", f"HTTP {resp.status_code}")
        log_event("warn", "unmask_denied",
                  user=username, customer_id=customer_id,
                  http_status=resp.status_code, error=err_msg)
        return jsonify({"error": err_msg}), resp.status_code

    except requests.exceptions.Timeout:
        log_event("error", "unmask_timeout", user=username, customer_id=customer_id)
        return jsonify({"error": "Request timed out"}), 504
    except Exception as e:
        log_event("error", "unmask_error", user=username, customer_id=customer_id)
        return jsonify({"error": str(e)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
