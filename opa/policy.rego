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
    # ── Legacy roles ──────────────────────────────────────────────────────────
    "agent":      ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],
    "supervisor": ["msisdn", "national_id"],
    "vip_agent":  [],
    "admin":      [],
    "partner":    ["name", "msisdn", "email", "national_id", "address",
                   "last_call_duration", "data_roaming_gb", "last_location"],

    # ── Care Operations ───────────────────────────────────────────────────────
    "care_l1":         ["msisdn", "email", "national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],
    "care_l2":         ["national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],
    "care_supervisor": ["national_id", "last_location"],

    # ── Technical Operations ──────────────────────────────────────────────────
    "noc_operator":     ["name", "email", "national_id", "address", "last_call_duration"],
    "field_technician": ["email", "national_id", "last_call_duration", "data_roaming_gb"],
    "roaming_ops":      ["name", "email", "national_id", "address", "last_call_duration"],

    # ── Business Operations ───────────────────────────────────────────────────
    "billing_agent":      ["email", "national_id", "address", "last_location"],
    "fraud_analyst":      [],
    "compliance_officer": [],

    # ── Audit ─────────────────────────────────────────────────────────────────
    "audit_viewer": ["name", "msisdn", "email", "national_id", "address",
                     "last_call_duration", "data_roaming_gb", "last_location"],

    # ── VIP & Premium ─────────────────────────────────────────────────────────
    "vip_care": [],

    # ── External Partners ─────────────────────────────────────────────────────
    "b2b_partner":  ["msisdn", "email", "national_id", "address",
                     "last_call_duration", "data_roaming_gb", "last_location"],
    "mvno_partner": ["name", "email", "national_id", "address",
                     "last_call_duration", "last_location"],

    # ── Administration ────────────────────────────────────────────────────────
    "data_admin": [],
}

backend_fields := f if {
    f := data.masking_config.backends[input.backend]
}
default backend_fields := {}

# ── VIP flag ──────────────────────────────────────────────────────────────────

is_vip := true if { vip_customers[input.customer_id] }
default is_vip := false

# ── Role classification sets ──────────────────────────────────────────────────

standard_roles := {
    "agent", "supervisor",
    "care_l1", "care_l2", "care_supervisor",
    "noc_operator", "field_technician", "roaming_ops",
    "billing_agent", "audit_viewer",
}

privileged_roles := {
    "vip_agent", "admin",
    "fraud_analyst", "compliance_officer", "vip_care", "data_admin",
}

partner_roles := {
    "partner",
    "b2b_partner", "mvno_partner",
}

# ── Access decision ───────────────────────────────────────────────────────────

default allow := false

allow if {
    standard_roles[input.role]
    not vip_customers[input.customer_id]
}

allow if {
    privileged_roles[input.role]
}

allow if {
    partner_roles[input.role]
    not vip_customers[input.customer_id]
    not startswith(input.path, "/api/unmask")
}

# ── Masked fields ─────────────────────────────────────────────────────────────

masked_fields := [] if {
    startswith(input.path, "/api/unmask")
} else := fields if {
    fields := role_masked_fields[input.role]
} else := []

# ── Decision entry point ──────────────────────────────────────────────────────

decision := {
    "allow":          allow,
    "is_vip":         is_vip,
    "masked_fields":  masked_fields,
    "backend_fields": backend_fields,
}
