package data_masking

# ── Config populated at runtime by admin-service ──────────────────────────────
vip_customers = c {
    c := data.masking_config.vip_customers
} else = {}

role_masked_fields = f {
    f := data.masking_config.role_masked_fields
} else = {
    "agent":      ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],
    "supervisor": ["msisdn", "national_id"],
    "vip_agent":  [],
    "admin":      [],
    "partner":    ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"]
}

# ── Backend field registry ───────────────────────────────────────────────────
default backend_fields = {}

backend_fields = f {
    f := data.masking_config.backends[input.backend]
}

# ── VIP flag ─────────────────────────────────────────────────────────────────
default is_vip = false

is_vip = true {
    vip_customers[input.customer_id]
}

# ── Access decision ───────────────────────────────────────────────────────────
default allow = false

allow {
    input.role == "agent"
    not vip_customers[input.customer_id]
}

allow {
    input.role == "supervisor"
    not vip_customers[input.customer_id]
}

allow {
    input.role == "vip_agent"
}

allow {
    input.role == "admin"
}

allow {
    input.role == "partner"
    not vip_customers[input.customer_id]
    not startswith(input.path, "/api/unmask")
}

# ── Masked fields ─────────────────────────────────────────────────────────────
# else-chain avoids multiple complete-rule definitions for the same name,
# which OPA v1.x flags even in --v0-compatible mode.
masked_fields = [] {
    startswith(input.path, "/api/unmask")
} else = fields {
    fields := role_masked_fields[input.role]
} else = []

# ── Decision entry point ──────────────────────────────────────────────────────
# OPA v1.x does not include `default`-only rule values in the package
# document query (/v1/data/data_masking).  An explicit complete rule
# that references the sub-rules is always emitted — even when the
# sub-rules resolve through their defaults — giving Kong a guaranteed
# non-undefined result at /v1/data/data_masking/decision.
decision = {
    "allow":         allow,
    "is_vip":        is_vip,
    "masked_fields": masked_fields,
    "backend_fields": backend_fields,
}
