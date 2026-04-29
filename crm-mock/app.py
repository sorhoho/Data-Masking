import os
import uuid
import threading
import requests as req_lib
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)

LOG_DASHBOARD_URL = os.environ.get("LOG_DASHBOARD_URL", "http://log-dashboard:9000/log")

CUSTOMERS = {
    "C001": {
        "id": "C001",
        "vip": True,
        # L1 – direct identifiers
        "name": "Ahmad bin Abdullah",
        "msisdn": "+60123456789",
        "email": "ahmad.abdullah@gmail.com",
        "national_id": "850315-14-5678",
        "address": "No. 12, Jalan Ampang, 50450 Kuala Lumpur",
        # account
        "account_id": "ACC-2024-001",
        "plan": "Postpaid 100GB",
        "monthly_charge": 99.00,
        "status": "active",
        "registration_date": "2021-03-15",
        "city": "Kuala Lumpur",
        "outstanding_balance": 0.00,
        "data_used_gb": 42.5,
        "last_payment_date": "2024-03-01",
        # L2 – linkable / profiling
        "last_call_duration": 342,
        "data_roaming_gb": 1.2,
        "last_location": "KLCC Tower 2, Kuala Lumpur",
    },
    "C002": {
        "id": "C002",
        "vip": False,
        "name": "Siti Nurhaliza binti Tarudin",
        "msisdn": "+60198765432",
        "email": "siti.nurhaliza@yahoo.com",
        "national_id": "920720-10-8812",
        "address": "Block 7, Jalan Mawar, 40150 Shah Alam",
        "account_id": "ACC-2024-002",
        "plan": "Prepaid 20GB",
        "monthly_charge": 30.00,
        "status": "active",
        "registration_date": "2022-07-20",
        "city": "Shah Alam",
        "outstanding_balance": 5.50,
        "data_used_gb": 18.1,
        "last_payment_date": "2024-02-28",
        "last_call_duration": 87,
        "data_roaming_gb": 0.0,
        "last_location": "Shah Alam Mall, Selangor",
    },
    "C003": {
        "id": "C003",
        "vip": False,
        "name": "Rajesh Kumar Sharma",
        "msisdn": "+60112233445",
        "email": "rajesh.sharma@hotmail.com",
        "national_id": "780505-07-3321",
        "address": "22A, Lorong Baru, 10050 George Town, Penang",
        "account_id": "ACC-2024-003",
        "plan": "Postpaid 50GB",
        "monthly_charge": 59.00,
        "status": "suspended",
        "registration_date": "2020-11-05",
        "city": "Penang",
        "outstanding_balance": 118.00,
        "data_used_gb": 0.0,
        "last_payment_date": "2024-01-15",
        "last_call_duration": 0,
        "data_roaming_gb": 0.0,
        "last_location": "Georgetown Heritage Zone, Penang",
    },
    "C004": {
        "id": "C004",
        "vip": True,
        "name": "Mei Ling Tan",
        "msisdn": "+60167890123",
        "email": "meiling.tan@outlook.com",
        "national_id": "880912-01-6649",
        "address": "Suite 3A, Straits Garden, 80000 Johor Bahru",
        "account_id": "ACC-2024-004",
        "plan": "Postpaid 200GB",
        "monthly_charge": 149.00,
        "status": "active",
        "registration_date": "2023-01-10",
        "city": "Johor Bahru",
        "outstanding_balance": 0.00,
        "data_used_gb": 95.3,
        "last_payment_date": "2024-03-05",
        "last_call_duration": 621,
        "data_roaming_gb": 4.8,
        "last_location": "Johor Premium Outlets, Johor",
    },
}


def _fire(entry):
    try:
        req_lib.post(LOG_DASHBOARD_URL, json=entry, timeout=0.5)
    except Exception:
        pass


def log_event(level, event, **kw):
    entry = {"service": "crm-mock", "level": level, "event": event, **kw}
    threading.Thread(target=_fire, args=(entry,), daemon=True).start()


# Index for O(1) MSISDN lookup
MSISDN_INDEX = {c["msisdn"]: cid for cid, c in CUSTOMERS.items()}

# Available subscription plans
PLANS = ["Prepaid 20GB", "Postpaid 50GB", "Postpaid 100GB", "Postpaid 200GB"]


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/resolve")
def resolve_customer():
    """Internal endpoint for Kong to map MSISDN → customer_id before calling OPA."""
    msisdn = request.args.get("msisdn", "").strip()
    if not msisdn:
        return jsonify({"error": "msisdn parameter required"}), 400
    cid = MSISDN_INDEX.get(msisdn)
    if not cid:
        return jsonify({"error": "Customer not found", "msisdn": msisdn}), 404
    customer = CUSTOMERS[cid]
    return jsonify({"customer_id": cid, "vip": customer["vip"]})


@app.get("/api/customer/<customer_id>")
def get_customer(customer_id):
    customer = CUSTOMERS.get(customer_id)
    if not customer:
        log_event("warn", "customer_fetched",
                  customer_id=customer_id, found=False, http_status=404)
        return jsonify({"error": "Customer not found", "id": customer_id}), 404
    log_event("info", "customer_fetched",
              customer_id=customer_id, found=True,
              plan=customer["plan"], status=customer["status"], http_status=200)
    return jsonify(customer)


@app.get("/api/customer")
def search_customer():
    """MSISDN-based customer lookup (same data as by-ID)."""
    msisdn = request.args.get("msisdn", "").strip()
    if not msisdn:
        return jsonify({"error": "msisdn query parameter required"}), 400
    cid = MSISDN_INDEX.get(msisdn)
    if not cid:
        log_event("warn", "customer_fetched",
                  msisdn_hint=msisdn[-4:] if len(msisdn) >= 4 else "****",
                  found=False, http_status=404)
        return jsonify({"error": "Customer not found", "msisdn": msisdn}), 404
    customer = CUSTOMERS[cid]
    log_event("info", "customer_fetched",
              customer_id=cid, found=True, lookup="msisdn",
              plan=customer["plan"], status=customer["status"], http_status=200)
    return jsonify(customer)


@app.post("/api/subscription")
def add_subscription():
    """Add a subscription plan to a customer identified by MSISDN."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400
    msisdn = (data.get("msisdn") or "").strip()
    plan   = (data.get("plan") or "").strip()
    if not msisdn or not plan:
        return jsonify({"error": "msisdn and plan are required"}), 400
    if plan not in PLANS:
        return jsonify({"error": f"Unknown plan. Valid plans: {PLANS}"}), 400
    cid = MSISDN_INDEX.get(msisdn)
    if not cid:
        return jsonify({"error": "Customer not found", "msisdn": msisdn}), 404
    customer = CUSTOMERS[cid]
    subscription_id = f"SUB-{uuid.uuid4().hex[:8].upper()}"
    log_event("info", "subscription_added",
              customer_id=cid, plan=plan,
              previous_plan=customer["plan"], http_status=200)
    return jsonify({
        "status":           "success",
        "subscription_id":  subscription_id,
        "customer_id":      cid,
        "msisdn":           msisdn,
        "plan":             plan,
        "previous_plan":    customer["plan"],
        "effective_date":   datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    })


@app.get("/api/customers")
def list_customers():
    summary = [
        {"id": c["id"], "account_id": c["account_id"],
         "status": c["status"], "vip": c["vip"]}
        for c in CUSTOMERS.values()
    ]
    return jsonify({"customers": summary, "total": len(summary)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
