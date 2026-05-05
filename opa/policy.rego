package data_masking

import rego.v1

# ── Bundle data (safe fallbacks when bundle not yet loaded) ───────────────────

vip_customers := data.masking_config.vip_customers if {
    data.masking_config.vip_customers
}
default vip_customers := {}

role_masked_fields := data.masking_config.role_masked_fields if {
    data.masking_config.role_masked_fields
}
default role_masked_fields := {
    "agent":      ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],
    "supervisor": ["msisdn", "national_id"],
    "vip_agent":  [],
    "admin":      [],
    "partner":    ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"]
}

backend_fields := f if {
    f := data.masking_config.backends[input.backend]
}
default backend_fields := {}

# ── VIP flag ──────────────────────────────────────────────────────────────────

is_vip := true if { vip_customers[input.customer_id] }
default is_vip := false

# ── Access decision ───────────────────────────────────────────────────────────

default allow := false

allow if {
    input.role == "agent"
    not vip_customers[input.customer_id]
}
allow if {
    input.role == "supervisor"
    not vip_customers[input.customer_id]
}
allow if { input.role == "vip_agent" }
allow if { input.role == "admin" }
allow if {
    input.role == "partner"
    not vip_customers[input.customer_id]
    not startswith(input.path, "/api/unmask")
}

# ── Masked fields ─────────────────────────────────────────────────────────────
# else-chain: only one branch fires per request, avoids conflicting
# complete-rule definitions that OPA v1 rejects at compile time.

masked_fields := [] if {
    startswith(input.path, "/api/unmask")
} else := fields if {
    fields := role_masked_fields[input.role]
} else := []

# ── Decision entry point ──────────────────────────────────────────────────────
# A concrete complete rule (not a default) that Kong queries at
# /v1/data/data_masking/decision.  All sub-rules have default values so
# this object is always fully defined — OPA v1 emits it in the result
# regardless of which sub-rules matched.

decision := {
    "allow":         allow,
    "is_vip":        is_vip,
    "masked_fields": masked_fields,
    "backend_fields": backend_fields,
}
