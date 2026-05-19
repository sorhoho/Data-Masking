"""
OPA client — queries data.data_masking.decision and returns masked_fields list.
Raises PermissionError if allow=false, requests.HTTPError on OPA failure.
"""
import os
import requests

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
_DECISION_PATH = "/v1/data/data_masking/decision"


def get_decision(role: str, customer_id: str, path: str = "/api/batch",
                 ctx: dict = None) -> dict:
    payload = {
        "input": {
            "role": role,
            "customer_id": customer_id,
            "path": path,
            "ctx": ctx or {},
        }
    }
    r = requests.post(OPA_URL + _DECISION_PATH, json=payload, timeout=5)
    r.raise_for_status()
    return r.json().get("result", {})


def get_masked_fields(role: str, customer_id: str, path: str = "/api/batch",
                      ctx: dict = None) -> list:
    """Return list of field names that should be masked for this role+customer."""
    decision = get_decision(role, customer_id, path=path, ctx=ctx)
    if not decision.get("allow", False):
        raise PermissionError(
            f"OPA denied: role={role!r} customer={customer_id!r} path={path!r}"
        )
    return decision.get("masked_fields", [])
