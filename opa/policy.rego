package data_masking

# ── Config populated at runtime by admin-service ──────────────────────────────
# Admin service PUTs to OPA's /v1/data/masking_config on startup and on every
# change, so these rules always reflect the current admin configuration.
# The else clauses are safe fallbacks in case data hasn't been pushed yet.

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

# ── VIP flag (returned to Kong for X-Access-Reference enforcement) ────────────
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

# Privileged roles: allowed for all customers (VIP header enforcement done in Kong)
allow {
    input.role == "vip_agent"
}

allow {
    input.role == "admin"
}

# Partner (machine-to-machine): full L1+L2 masking, no VIP access, no unmask
allow {
    input.role == "partner"
    not vip_customers[input.customer_id]
    not startswith(input.path, "/api/unmask")
}

# ── Masked fields (empty = no masking) ───────────────────────────────────────
default masked_fields = []

# Unmask endpoint: caller explicitly requested full data
masked_fields = [] {
    startswith(input.path, "/api/unmask")
}

# Regular endpoint: role-based masking from admin-configured rules
masked_fields = fields {
    not startswith(input.path, "/api/unmask")
    fields := role_masked_fields[input.role]
}
