import os
import threading
import requests as req_lib
from flask import Flask, jsonify, request

app = Flask(__name__)

LOG_DASHBOARD_URL = os.environ.get("LOG_DASHBOARD_URL", "http://log-dashboard:9000/log")

# Same customers as CRM but with billing-system field names.
# Field alias map (vs CRM):
#   mobilenum       ← msisdn          (L1)
#   subname         ← name            (L1)
#   ic_num          ← national_id     (L1)
#   billing_address ← address         (L1)
#   call_duration_s ← last_call_duration (L2)
#   roaming_gb      ← data_roaming_gb (L2)
# email and last_location have no billing equivalent.
SUBSCRIBERS = {
    "+60123456789": {
        "mobilenum":        "+60123456789",
        "subname":          "Ahmad bin Abdullah",
        "ic_num":           "850315-14-5678",
        "billing_address":  "No. 12, Jalan Ampang, 50450 Kuala Lumpur",
        "account_type":     "postpaid",
        "plan_code":        "PP100",
        "outstanding_bill": 0.00,
        "last_bill_date":   "2024-03-01",
        "data_usage_gb":    42.5,
        "call_duration_s":  342,
        "roaming_gb":       1.2,
    },
    "+60198765432": {
        "mobilenum":        "+60198765432",
        "subname":          "Siti Nurhaliza binti Tarudin",
        "ic_num":           "920720-10-8812",
        "billing_address":  "Block 7, Jalan Mawar, 40150 Shah Alam",
        "account_type":     "prepaid",
        "plan_code":        "PRE20",
        "outstanding_bill": 5.50,
        "last_bill_date":   "2024-02-28",
        "data_usage_gb":    18.1,
        "call_duration_s":  87,
        "roaming_gb":       0.0,
    },
    "+60112233445": {
        "mobilenum":        "+60112233445",
        "subname":          "Rajesh Kumar Sharma",
        "ic_num":           "780505-07-3321",
        "billing_address":  "22A, Lorong Baru, 10050 George Town, Penang",
        "account_type":     "postpaid",
        "plan_code":        "PP50",
        "outstanding_bill": 118.00,
        "last_bill_date":   "2024-01-15",
        "data_usage_gb":    0.0,
        "call_duration_s":  0,
        "roaming_gb":       0.0,
    },
    "+60167890123": {
        "mobilenum":        "+60167890123",
        "subname":          "Mei Ling Tan",
        "ic_num":           "880912-01-6649",
        "billing_address":  "Suite 3A, Straits Garden, 80000 Johor Bahru",
        "account_type":     "postpaid",
        "plan_code":        "PP200",
        "outstanding_bill": 0.00,
        "last_bill_date":   "2024-03-05",
        "data_usage_gb":    95.3,
        "call_duration_s":  621,
        "roaming_gb":       4.8,
    },
}


def _fire(entry):
    try:
        req_lib.post(LOG_DASHBOARD_URL, json=entry, timeout=0.5)
    except Exception:
        pass


def log_event(level, event, **kw):
    entry = {"service": "billing-mock", "level": level, "event": event, **kw}
    threading.Thread(target=_fire, args=(entry,), daemon=True).start()


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/billing/subscriber")
def get_subscriber():
    msisdn = request.args.get("msisdn", "").strip()
    if not msisdn:
        return jsonify({"error": "msisdn query parameter required"}), 400
    sub = SUBSCRIBERS.get(msisdn)
    if not sub:
        log_event("warn", "subscriber_fetched",
                  msisdn_hint=msisdn[-4:] if len(msisdn) >= 4 else "****",
                  found=False, http_status=404)
        return jsonify({"error": "Subscriber not found", "msisdn": msisdn}), 404
    log_event("info", "subscriber_fetched",
              msisdn_hint=msisdn[-4:] if len(msisdn) >= 4 else "****",
              plan_code=sub["plan_code"], http_status=200)
    return jsonify(sub)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
