"""
Data Warehouse / Lake / Mart masking service.

Exposes:
  POST /export          — query PostgreSQL, mask, write Parquet to MinIO
  POST /views/refresh   — generate masked SQL VIEWs per role in PostgreSQL
  POST /marts/build     — build per-business-unit mart schemas
  GET  /                — dashboard: bucket stats, view counts, recent exports
  GET  /health          — liveness probe
"""
import io
import json
import os
import sys
import logging
from datetime import datetime, timezone

import boto3
import pandas as pd
import psycopg2
import psycopg2.extras
import pyarrow as pa
import pyarrow.parquet as pq
import requests
from botocore.exceptions import ClientError
from flask import Flask, jsonify, render_template_string, request

sys.path.insert(0, "/app")
from masking_sdk.masking import apply_masking, MASKERS
from masking_sdk.opa_client import get_masked_fields, OPA_URL

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    stream=sys.stdout)
log = logging.getLogger("dw-masker")

app = Flask(__name__)

DB_URL          = os.getenv("DB_URL", "postgresql://adminuser:admin_pass@postgres:5432/admindb")
MINIO_ENDPOINT  = os.getenv("MINIO_ENDPOINT",  "http://minio:9000")
MINIO_ACCESS    = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET    = os.getenv("MINIO_SECRET_KEY", "minioadmin123")
MINIO_BUCKET    = os.getenv("MINIO_BUCKET",     "masked-exports")
ADMIN_URL       = os.getenv("ADMIN_SERVICE_URL", "http://admin-service:8888")

# ── Mart definitions: schema → list of roles ─────────────────────────────────

MART_DEFINITIONS = {
    "mart_care":    ["care_l1", "care_l2", "care_supervisor"],
    "mart_billing": ["billing_agent"],
    "mart_fraud":   ["fraud_analyst", "compliance_officer"],
    "mart_ops":     ["noc_operator", "field_technician", "roaming_ops"],
    "mart_partner": ["partner", "b2b_partner", "mvno_partner"],
}

# ── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)


def get_role_masked_fields() -> dict:
    """Return {role: [masked_field, ...]} from admin-service DB."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT role, field FROM role_field_masks ORDER BY role, field")
            rows = cur.fetchall()
    finally:
        conn.close()
    result: dict = {}
    for r in rows:
        result.setdefault(r["role"], []).append(r["field"])
    return result


# ── MinIO helpers ─────────────────────────────────────────────────────────────

def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ACCESS,
        aws_secret_access_key=MINIO_SECRET,
    )


def ensure_bucket(s3):
    try:
        s3.head_bucket(Bucket=MINIO_BUCKET)
    except ClientError:
        s3.create_bucket(Bucket=MINIO_BUCKET)
        log.info("Created bucket %s", MINIO_BUCKET)


# ── SQL view generators ───────────────────────────────────────────────────────

# Inline SQL masking expressions per canonical field (PostgreSQL syntax)
_SQL_MASKERS = {
    "email": (
        "CASE WHEN {col} IS NULL THEN NULL "
        "WHEN position('@' IN {col}) <= 2 THEN repeat('*', length({col})) "
        "ELSE left({col}, 1) || repeat('*', greatest(position('@' IN {col})-2,0)) "
        "|| substr({col}, position('@' IN {col})-1) END"
    ),
    "msisdn": (
        "CASE WHEN {col} IS NULL THEN NULL "
        "WHEN {col} ~ '^\\+\\d{{1,2}}\\d{{2,}}$' THEN "
        "  left({col}, 3) || repeat('*', greatest(length({col})-5,0)) || right({col}, 2) "
        "ELSE repeat('*', length({col})) END"
    ),
    "name": (
        "CASE WHEN {col} IS NULL THEN NULL "
        "ELSE regexp_replace({col}, '(\\w)(\\w+)', '\\1***', 'g') END"
    ),
    "national_id": (
        "CASE WHEN {col} IS NULL THEN NULL "
        "WHEN length({col}) <= 2 THEN repeat('*', length({col})) "
        "ELSE left({col}, 2) || repeat('*', length({col})-2) END"
    ),
    "address": "CASE WHEN {col} IS NULL THEN NULL ELSE '*** (redacted)' END",
    "last_call_duration": "CASE WHEN {col} IS NULL THEN NULL ELSE '***' END",
    "data_roaming_gb":    "CASE WHEN {col} IS NULL THEN NULL ELSE '***' END",
    "last_location":      "CASE WHEN {col} IS NULL THEN NULL ELSE '***' END",
}

# Canonical table columns we manage (matches fields across CRM/billing mocks)
_RAW_TABLE_COLUMNS = [
    "customer_id", "name", "msisdn", "email", "national_id", "address",
    "last_call_duration", "data_roaming_gb", "last_location",
]


def _view_column_sql(col: str, masked_fields: list) -> str:
    if col not in masked_fields or col not in _SQL_MASKERS:
        return col
    return _SQL_MASKERS[col].format(col=col) + f" AS {col}"


def _generate_view_ddl(schema: str, role: str, masked_fields: list) -> str:
    col_exprs = [_view_column_sql(c, masked_fields) for c in _RAW_TABLE_COLUMNS]
    cols_sql  = ",\n  ".join(col_exprs)
    return (
        f"CREATE SCHEMA IF NOT EXISTS {schema};\n"
        f"CREATE OR REPLACE VIEW {schema}.customers AS\n"
        f"SELECT\n  {cols_sql}\n"
        f"FROM customer_tiers ct\n"
        f"  LEFT JOIN LATERAL (SELECT 1) dummy ON TRUE;\n"
        f"-- role: {role}  masked: {masked_fields}"
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/export")
def export_to_lake():
    """
    Body: {"role": "agent", "records": [{...}, ...]}
    OR:   {"role": "agent", "customer_ids": ["C001", "C002"]}

    Masks records using OPA, writes Parquet to MinIO.
    Returns S3 path and row count.
    """
    body = request.get_json(force=True) or {}
    role = body.get("role", "").strip()
    if not role:
        return jsonify({"error": "role required"}), 400

    records = body.get("records")
    if not records:
        # Fetch from DB by customer_ids (or all if none specified)
        customer_ids = body.get("customer_ids")
        conn = get_db()
        try:
            with conn.cursor() as cur:
                if customer_ids:
                    cur.execute(
                        "SELECT customer_id, tier AS customer_tier FROM customer_tiers "
                        "WHERE customer_id = ANY(%s)",
                        (customer_ids,)
                    )
                else:
                    cur.execute(
                        "SELECT customer_id, tier AS customer_tier FROM customer_tiers"
                    )
                records = [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    if not records:
        return jsonify({"error": "no records found"}), 404

    # Mask each record — group by customer_id to minimise OPA calls
    masked_rows = []
    errors = []
    for rec in records:
        cid = str(rec.get("customer_id", ""))
        try:
            mf = get_masked_fields(role, cid, path="/api/export")
            masked_rows.append(apply_masking(rec, mf))
        except PermissionError as exc:
            errors.append({"customer_id": cid, "error": str(exc)})
        except Exception as exc:
            errors.append({"customer_id": cid, "error": f"opa_error: {exc}"})

    if not masked_rows:
        return jsonify({"error": "all records denied", "details": errors}), 403

    # Write Parquet to MinIO
    df  = pd.DataFrame(masked_rows)
    buf = io.BytesIO()
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), buf)
    buf.seek(0)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    s3_key   = f"{role}/customers/{ts}.parquet"
    s3       = s3_client()
    ensure_bucket(s3)
    s3.put_object(Bucket=MINIO_BUCKET, Key=s3_key, Body=buf.getvalue(),
                  ContentType="application/octet-stream")

    # Track in DB
    try:
        conn = get_db()
        policy_ver = _get_policy_version()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO dw_exports (exported_at, role, table_name, row_count, "
                "s3_path, policy_version) VALUES (%s,%s,%s,%s,%s,%s)",
                (datetime.now(timezone.utc).isoformat(), role, "customers",
                 len(masked_rows), f"s3://{MINIO_BUCKET}/{s3_key}", policy_ver)
            )
        conn.commit()
        conn.close()
    except Exception as exc:
        log.warning("Failed to log export: %s", exc)

    log.info("Exported %d rows for role=%s → s3://%s/%s",
             len(masked_rows), role, MINIO_BUCKET, s3_key)
    return jsonify({
        "s3_path":       f"s3://{MINIO_BUCKET}/{s3_key}",
        "rows":          len(masked_rows),
        "denied":        len(errors),
        "policy_version": _get_policy_version(),
    })


@app.post("/views/refresh")
def refresh_views():
    """
    Generate/refresh a masked SQL VIEW per role in PostgreSQL.
    Schema name: masked_<role>  (e.g. masked_agent)
    """
    role_masks = get_role_masked_fields()
    conn = get_db()
    created = []
    errors  = []
    try:
        for role, masked_fields in role_masks.items():
            schema = f"masked_{role.replace('-', '_')}"
            ddl = _generate_view_ddl(schema, role, masked_fields)
            try:
                with conn.cursor() as cur:
                    for stmt in ddl.split(";"):
                        stmt = stmt.strip()
                        if stmt and not stmt.startswith("--"):
                            cur.execute(stmt)
                conn.commit()
                created.append({"schema": schema, "role": role,
                                 "masked_fields": masked_fields})
            except Exception as exc:
                conn.rollback()
                errors.append({"role": role, "error": str(exc)})
                log.warning("View creation failed for %s: %s", role, exc)
    finally:
        conn.close()

    log.info("Views refreshed: %d created, %d errors", len(created), len(errors))
    return jsonify({"views_created": len(created), "views": created, "errors": errors})


@app.post("/marts/build")
def build_marts():
    """
    Create mart schemas — one schema per business unit, views per role.
    Mart definitions come from MART_DEFINITIONS constant.
    """
    role_masks = get_role_masked_fields()
    conn = get_db()
    built  = []
    errors = []
    try:
        for mart_schema, roles in MART_DEFINITIONS.items():
            for role in roles:
                masked_fields = role_masks.get(role, [])
                view_name = f"{mart_schema}.{role.replace('-', '_')}_customers"
                ddl = (
                    f"CREATE SCHEMA IF NOT EXISTS {mart_schema};\n"
                    f"CREATE OR REPLACE VIEW {view_name} AS\n"
                    f"SELECT * FROM masked_{role.replace('-','_')}.customers;"
                )
                try:
                    with conn.cursor() as cur:
                        for stmt in ddl.split(";"):
                            stmt = stmt.strip()
                            if stmt:
                                cur.execute(stmt)
                    conn.commit()
                    built.append({"mart": mart_schema, "role": role, "view": view_name})
                except Exception as exc:
                    conn.rollback()
                    errors.append({"mart": mart_schema, "role": role, "error": str(exc)})
    finally:
        conn.close()

    return jsonify({"views_built": len(built), "marts": built, "errors": errors})


@app.get("/exports")
def list_exports():
    """List recent exports from dw_exports table."""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM dw_exports ORDER BY id DESC LIMIT 50"
            )
            rows = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()
    return jsonify(rows)


@app.get("/")
def dashboard():
    # MinIO stats
    s3 = s3_client()
    bucket_stats = {"error": None, "objects": 0, "roles": []}
    try:
        ensure_bucket(s3)
        paginator = s3.get_paginator("list_objects_v2")
        role_counts: dict = {}
        total = 0
        for page in paginator.paginate(Bucket=MINIO_BUCKET):
            for obj in page.get("Contents", []):
                total += 1
                role = obj["Key"].split("/")[0]
                role_counts[role] = role_counts.get(role, 0) + 1
        bucket_stats["objects"] = total
        bucket_stats["roles"]   = [{"role": k, "files": v}
                                    for k, v in sorted(role_counts.items())]
    except Exception as exc:
        bucket_stats["error"] = str(exc)

    # Recent exports
    recent = []
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM dw_exports ORDER BY id DESC LIMIT 10")
            recent = [dict(r) for r in cur.fetchall()]
        conn.close()
    except Exception:
        pass

    return render_template_string(_DASHBOARD_HTML,
                                  bucket=MINIO_BUCKET,
                                  stats=bucket_stats,
                                  recent=recent,
                                  minio_console=MINIO_ENDPOINT.replace(":9000", ":9001"))


def _get_policy_version() -> int | None:
    try:
        r = requests.get(f"{ADMIN_URL}/api/policy-version", timeout=3)
        return r.json().get("version")
    except Exception:
        return None


# ── Simple dashboard template ─────────────────────────────────────────────────

_DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DW Masker</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">
<nav class="navbar navbar-dark bg-dark px-4">
  <span class="navbar-brand fw-bold">&#128202; DW / Lake / Mart Masker</span>
  <div class="d-flex gap-2">
    <a href="{{minio_console}}" target="_blank" class="btn btn-sm btn-outline-warning">MinIO Console &#8599;</a>
  </div>
</nav>
<div class="container py-4" style="max-width:960px">

  {% if stats.error %}
  <div class="alert alert-warning">MinIO not reachable: {{stats.error}}</div>
  {% else %}
  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="card text-center">
        <div class="card-body">
          <h2>{{stats.objects}}</h2><small class="text-muted">Parquet files in <code>{{bucket}}</code></small>
        </div>
      </div>
    </div>
    {% for rs in stats.roles %}
    <div class="col-md-4">
      <div class="card text-center">
        <div class="card-body">
          <h2>{{rs.files}}</h2><small class="text-muted">{{rs.role}}</small>
        </div>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  <div class="row g-3 mb-4">
    <div class="col-md-6">
      <div class="card">
        <div class="card-header fw-bold">Export to Data Lake</div>
        <div class="card-body">
          <form id="exportForm">
            <div class="mb-2">
              <label class="form-label">Role</label>
              <input name="role" class="form-control form-control-sm" placeholder="agent" required>
            </div>
            <div class="mb-2">
              <label class="form-label">Customer IDs (comma-separated, blank = all)</label>
              <input name="customer_ids" class="form-control form-control-sm" placeholder="C001,C002">
            </div>
            <button type="submit" class="btn btn-sm btn-primary">Export Parquet</button>
          </form>
          <div id="exportResult" class="mt-2 small"></div>
        </div>
      </div>
    </div>
    <div class="col-md-6">
      <div class="card">
        <div class="card-header fw-bold">Manage Views &amp; Marts</div>
        <div class="card-body d-flex flex-column gap-2">
          <button class="btn btn-sm btn-outline-secondary" onclick="postAndShow('/views/refresh','viewResult')">
            Refresh Masked Views
          </button>
          <button class="btn btn-sm btn-outline-secondary" onclick="postAndShow('/marts/build','viewResult')">
            Build Mart Schemas
          </button>
          <pre id="viewResult" class="mt-2 small bg-white p-2 border rounded" style="max-height:120px;overflow:auto"></pre>
        </div>
      </div>
    </div>
  </div>

  <h6 class="fw-bold">Recent Exports</h6>
  <table class="table table-sm table-bordered bg-white">
    <thead class="table-dark"><tr>
      <th>ID</th><th>Exported At</th><th>Role</th><th>Rows</th><th>S3 Path</th><th>Policy Version</th>
    </tr></thead>
    <tbody>
    {% for e in recent %}
    <tr>
      <td>{{e.id}}</td>
      <td>{{e.exported_at}}</td>
      <td>{{e.role}}</td>
      <td>{{e.row_count}}</td>
      <td><code>{{e.s3_path}}</code></td>
      <td>{{e.policy_version or 'draft'}}</td>
    </tr>
    {% endfor %}
    {% if not recent %}
    <tr><td colspan="6" class="text-center text-muted">No exports yet</td></tr>
    {% endif %}
    </tbody>
  </table>
</div>
<script>
document.getElementById('exportForm').addEventListener('submit', async e => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {role: fd.get('role')};
  const ids = fd.get('customer_ids').trim();
  if (ids) body.customer_ids = ids.split(',').map(s=>s.trim()).filter(Boolean);
  const r = await fetch('/export', {method:'POST',
    headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const d = await r.json();
  document.getElementById('exportResult').textContent = JSON.stringify(d, null, 2);
});
async function postAndShow(url, target) {
  const r = await fetch(url, {method:'POST',
    headers:{'Content-Type':'application/json'}, body:'{}'});
  const d = await r.json();
  document.getElementById(target).textContent = JSON.stringify(d, null, 2);
}
</script>
</body></html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=False)
