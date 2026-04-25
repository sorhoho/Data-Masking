import os
import threading
import requests as req_lib
from flask import Flask, jsonify, request

app = Flask(__name__)

LOG_DASHBOARD_URL = os.environ.get("LOG_DASHBOARD_URL", "http://log-dashboard:9000/log")

CUSTOMERS = {
    "C001": {
        "id": "C001",
        "name": "Ahmad bin Abdullah",
        "msisdn": "+60123456789",
        "email": "ahmad.abdullah@gmail.com",
        "account_id": "ACC-2024-001",
        "plan": "Postpaid 100GB",
        "monthly_charge": 99.00,
        "status": "active",
        "registration_date": "2021-03-15",
        "city": "Kuala Lumpur",
        "outstanding_balance": 0.00,
        "data_used_gb": 42.5,
        "last_payment_date": "2024-03-01"
    },
    "C002": {
        "id": "C002",
        "name": "Siti Nurhaliza binti Tarudin",
        "msisdn": "+60198765432",
        "email": "siti.nurhaliza@yahoo.com",
        "account_id": "ACC-2024-002",
        "plan": "Prepaid 20GB",
        "monthly_charge": 30.00,
        "status": "active",
        "registration_date": "2022-07-20",
        "city": "Shah Alam",
        "outstanding_balance": 5.50,
        "data_used_gb": 18.1,
        "last_payment_date": "2024-02-28"
    },
    "C003": {
        "id": "C003",
        "name": "Rajesh Kumar Sharma",
        "msisdn": "+60112233445",
        "email": "rajesh.sharma@hotmail.com",
        "account_id": "ACC-2024-003",
        "plan": "Postpaid 50GB",
        "monthly_charge": 59.00,
        "status": "suspended",
        "registration_date": "2020-11-05",
        "city": "Penang",
        "outstanding_balance": 118.00,
        "data_used_gb": 0.0,
        "last_payment_date": "2024-01-15"
    },
    "C004": {
        "id": "C004",
        "name": "Mei Ling Tan",
        "msisdn": "+60167890123",
        "email": "meiling.tan@outlook.com",
        "account_id": "ACC-2024-004",
        "plan": "Postpaid 200GB",
        "monthly_charge": 149.00,
        "status": "active",
        "registration_date": "2023-01-10",
        "city": "Johor Bahru",
        "outstanding_balance": 0.00,
        "data_used_gb": 95.3,
        "last_payment_date": "2024-03-05"
    }
}


def _fire(entry):
    try:
        req_lib.post(LOG_DASHBOARD_URL, json=entry, timeout=0.5)
    except Exception:
        pass


def log_event(level, event, **kw):
    entry = {"service": "crm-mock", "level": level, "event": event, **kw}
    threading.Thread(target=_fire, args=(entry,), daemon=True).start()


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


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


@app.get("/api/customers")
def list_customers():
    summary = [
        {"id": c["id"], "account_id": c["account_id"], "status": c["status"]}
        for c in CUSTOMERS.values()
    ]
    return jsonify({"customers": summary, "total": len(summary)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
