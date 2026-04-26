package data_masking

# ── VIP customer IDs ──────────────────────────────────────────────────────────
vip_customers = {"C001", "C004"}

# ── Role → masked fields ──────────────────────────────────────────────────────
#   Classification:
#     L1 (direct identifiers): name, msisdn, email, national_id, address
#     L2 (linkable/profiling): last_call_duration, data_roaming_gb, last_location
#
#   agent:      all L1 + all L2 masked
#   supervisor: sensitive L1 only (msisdn, national_id)
#   vip_agent:  no masking (full PII access, VIP-authorised)
#   admin:      no masking
role_masked_fields = {
    "agent":      ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],
    "supervisor": ["msisdn", "national_id"],
    "vip_agent":  [],
    "admin":      []
}

# ── VIP flag (returned to Kong for header enforcement) ────────────────────────
default is_vip = false

is_vip = true {
    vip_customers[input.customer_id]
}

# ── Access decision ───────────────────────────────────────────────────────────
default allow = false

# Regular roles: denied for VIP customers
allow {
    input.role == "agent"
    not vip_customers[input.customer_id]
}

allow {
    input.role == "supervisor"
    not vip_customers[input.customer_id]
}

# Privileged roles: allowed for all customers (VIP enforcement done in Kong)
allow {
    input.role == "vip_agent"
}

allow {
    input.role == "admin"
}

# ── Masked fields (empty = no masking) ───────────────────────────────────────
default masked_fields = []

# Unmask endpoint: caller explicitly requested full data
masked_fields = [] {
    startswith(input.path, "/api/unmask")
}

# Regular endpoint: role-based masking
masked_fields = fields {
    not startswith(input.path, "/api/unmask")
    fields := role_masked_fields[input.role]
}
