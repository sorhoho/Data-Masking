import os
import requests
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

KEYCLOAK_URL          = os.environ.get("KEYCLOAK_URL",          "http://localhost:8080")
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KONG_URL              = os.environ.get("KONG_URL",              "http://kong:8000")
REALM                 = "demo"

# ── Keycloak OIDC client ──────────────────────────────────────────────────────
# authorize_url   → browser-facing (uses KEYCLOAK_URL = localhost:8080)
# access_token_url → server-to-server (uses KEYCLOAK_INTERNAL_URL = keycloak:8080)
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
    from functools import wraps
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
    token = oauth.keycloak.authorize_access_token()
    access_token = token["access_token"]

    # Fetch userinfo server-side (internal URL)
    ui_resp = requests.get(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=8,
    )
    userinfo = ui_resp.json() if ui_resp.ok else {}
    userinfo["_access_token"] = access_token   # handy for debug panel

    session["user"]         = userinfo
    session["access_token"] = access_token
    return redirect(url_for("search"))


@app.get("/logout")
def logout():
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
    access_token = session["access_token"]
    try:
        resp = requests.get(
            f"{KONG_URL}/api/customer/{customer_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            return render_template(
                "customer.html",
                customer=resp.json(),
                error=None,
                user=current_user(),
                customer_id=customer_id,
            )
        if resp.status_code in (401, 403):
            err_body = resp.json() if resp.content else {}
            error = err_body.get("message", f"HTTP {resp.status_code}: Access denied")
        elif resp.status_code == 404:
            error = f"Customer '{customer_id}' not found in CRM"
        else:
            error = f"Upstream error – HTTP {resp.status_code}"
    except requests.exceptions.ConnectionError:
        error = "Cannot reach Kong API Gateway. Is it running?"
    except requests.exceptions.Timeout:
        error = "Request timed out."

    return render_template(
        "customer.html",
        customer=None,
        error=error,
        user=current_user(),
        customer_id=customer_id,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=False)
