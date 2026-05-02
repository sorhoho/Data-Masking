import json
import os
import queue
import threading
import time
from collections import deque
from datetime import datetime, timezone

import requests
from flask import Flask, Response, jsonify, render_template, request, stream_with_context

LOKI_URL = os.environ.get("LOKI_URL", "http://loki:3100/loki/api/v1/push")

app = Flask(__name__)

MAX_LOGS    = 500
log_buffer  = deque(maxlen=MAX_LOGS)
buffer_lock = threading.Lock()
subscribers = []
subs_lock   = threading.Lock()


def push_to_loki(entry):
    """Forward a log entry to Loki. Fire-and-forget — never blocks callers."""
    try:
        labels = {
            "job":     "data-masking",
            "service": entry.get("service", "unknown"),
            "level":   entry.get("level",   "info"),
        }
        ts_ns   = str(int(time.time() * 1e9))
        payload = {
            "streams": [{
                "stream": labels,
                "values": [[ts_ns, json.dumps(entry)]],
            }]
        }
        requests.post(LOKI_URL, json=payload, timeout=1)
    except Exception:
        pass  # Loki failure must never surface to callers


def broadcast(entry):
    with subs_lock:
        dead = []
        for q in subscribers:
            try:
                q.put_nowait(entry)
            except queue.Full:
                dead.append(q)
        for q in dead:
            subscribers.remove(q)


@app.post("/log")
def receive_log():
    entry = request.get_json(silent=True) or {}
    if not entry:
        return jsonify({"ok": False, "error": "empty body"}), 400
    entry.setdefault("timestamp", datetime.now(timezone.utc).strftime("%H:%M:%S"))
    entry.setdefault("service", "unknown")
    entry.setdefault("level",   "info")
    with buffer_lock:
        log_buffer.append(entry)
    broadcast(entry)
    threading.Thread(target=push_to_loki, args=(entry,), daemon=True).start()
    return jsonify({"ok": True})


@app.get("/logs")
def get_logs():
    with buffer_lock:
        return jsonify(list(log_buffer))


@app.post("/clear")
def clear_logs():
    with buffer_lock:
        log_buffer.clear()
    return jsonify({"ok": True})


@app.get("/stream")
def stream():
    q = queue.Queue(maxsize=100)
    with subs_lock:
        subscribers.append(q)

    @stream_with_context
    def generate():
        try:
            while True:
                try:
                    entry = q.get(timeout=20)
                    yield f"data: {json.dumps(entry)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with subs_lock:
                try:
                    subscribers.remove(q)
                except ValueError:
                    pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok", "log_count": len(log_buffer)})


@app.get("/")
def dashboard():
    with buffer_lock:
        logs = list(log_buffer)
    return render_template("dashboard.html", logs=logs)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, threaded=True, debug=False)
