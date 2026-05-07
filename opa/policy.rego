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
    # L1: first-line triage — name visible, everything else masked
    "care_l1":         ["msisdn", "email", "national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],
    # L2: callbacks and escalations — contact details unmasked, PII still hidden
    "care_l2":         ["national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],
    # Supervisor: full care context for escalation; national_id and location masked
    "care_supervisor": ["national_id", "last_location"],

    # ── Technical Operations ──────────────────────────────────────────────────
    # NOC: network-focused — MSISDN, roaming, location visible; no identity PII
    "noc_operator":    ["name", "email", "national_id", "address", "last_call_duration"],
    # Field tech: needs name, MSISDN, address and location for site visits
    "field_technician":["email", "national_id", "last_call_duration", "data_roaming_gb"],
    # Roaming ops: MSISDN + roaming data; personal identity not needed
    "roaming_ops":     ["name", "email", "national_id", "address", "last_call_duration"],

    # ── Business Operations ───────────────────────────────────────────────────
    # Billing: sees charges + name/MSISDN; no address, email, national_id
    "billing_agent":   ["email", "national_id", "address", "last_location"],
    # Fraud analyst: full unmasked — investigation requires complete picture
    "fraud_analyst":   [],
    # Compliance: full access for regulatory audit; all events logged
    "compliance_officer": [],

    # ── Audit ─────────────────────────────────────────────────────────────────
    # Audit viewer: schema/metadata access only — never sees raw PII
    "audit_viewer":    ["name", "msisdn", "email", "national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],

    # ── VIP & Premium ─────────────────────────────────────────────────────────
    "vip_care":        [],

    # ── External Partners ─────────────────────────────────────────────────────
    # B2B partner: name visible for business context; all contact/PII masked
    "b2b_partner":     ["msisdn", "email", "national_id", "address",
                        "last_call_duration", "data_roaming_gb", "last_location"],
    # MVNO partner: MSISDN + roaming for subscriber management
    "mvno_partner":    ["name", "email", "national_id", "address",
                        "last_call_duration", "last_location"],

    # ── Administration ────────────────────────────────────────────────────────
    "data_admin":      [],
}

backend_fields := f if {
    f := data.masking_config.backends[input.backend]
}
default backend_fields := {}

# ── VIP flag ──────────────────────────────────────────────────────────────────

is_vip := true if { vip_customers[input.customer_id] }
default is_vip := false

# ── Role classification sets ──────────────────────────────────────────────────

# Standard roles: serve non-VIP customers only
standard_roles := {
    "agent", "supervisor",
    "care_l1", "care_l2", "care_supervisor",
    "noc_operator", "field_technician", "roaming_ops",
    "billing_agent", "audit_viewer",
}

# Privileged roles: can serve any customer including VIP
privileged_roles := {
    "vip_agent", "admin",
    "fraud_analyst", "compliance_officer", "vip_care", "data_admin",
}

# External partner roles: non-VIP only, blocked from unmask endpoints
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
    "allow":         allow,
    "is_vip":        is_vip,
    "masked_fields": masked_fields,
    "backend_fields": backend_fields,
}
