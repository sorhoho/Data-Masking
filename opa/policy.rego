package data_masking

import rego.v1

# ── Bundle data (safe fallbacks when bundle not yet loaded) ───────────────────

customer_tiers := data.masking_config.customer_tiers if {
    data.masking_config.customer_tiers
}
default customer_tiers := {}

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

# ── Customer tier ─────────────────────────────────────────────────────────────

customer_tier := customer_tiers[input.customer_id] if {
    customer_tiers[input.customer_id]
}
default customer_tier := "standard"

is_vip := true if { customer_tier == "vip" }
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

# Roles permitted on risk-flagged customers
risk_access_roles := {
    "fraud_analyst", "compliance_officer",
    "care_supervisor", "data_admin", "admin",
}

# Roles permitted on premium customers (care_l2 and above standard tier)
premium_access_roles := {
    "care_l2", "care_supervisor", "supervisor",
    "billing_agent", "roaming_ops", "noc_operator",
    "field_technician", "audit_viewer",
}

# ── Access decision ───────────────────────────────────────────────────────────

default allow := false

# Standard tier: all standard + privileged + partner roles
allow if {
    standard_roles[input.role]
    customer_tier == "standard"
}

# Premium tier: elevated standard roles + all privileged
allow if {
    premium_access_roles[input.role]
    customer_tier == "premium"
}

# VIP tier: privileged roles only
allow if {
    privileged_roles[input.role]
    customer_tier == "vip"
}

# Risk tier: restricted to risk_access_roles only
allow if {
    risk_access_roles[input.role]
    customer_tier == "risk"
}

# Privileged roles on standard and premium tiers (not covered by VIP/risk rules above)
allow if {
    privileged_roles[input.role]
    customer_tier == "standard"
}
allow if {
    privileged_roles[input.role]
    customer_tier == "premium"
}

# Partner roles: standard tier only, no unmask paths
allow if {
    partner_roles[input.role]
    customer_tier == "standard"
    not startswith(input.path, "/api/unmask")
}

# ── Context signals (safe defaults when ctx absent) ───────────────────────────

default _in_working_hours := true
_in_working_hours := input.ctx.in_working_hours if {
    is_boolean(input.ctx.in_working_hours)
}

default _initiated_by := "customer"
_initiated_by := input.ctx.initiated_by if {
    is_string(input.ctx.initiated_by)
    input.ctx.initiated_by != ""
}

default _channel := "web"
_channel := input.ctx.channel if {
    is_string(input.ctx.channel)
    input.ctx.channel != ""
}

default _session_type := "normal"
_session_type := input.ctx.session_type if {
    is_string(input.ctx.session_type)
    input.ctx.session_type != ""
}

# ── Unmask token: approved fields are subtracted from masking ─────────────────

_token_unmasked contains f if {
    input.unmask.valid == true
    f := input.unmask.fields[_]
}

# ── Context-driven extra masking ──────────────────────────────────────────────

# Out-of-hours: first-line care and billing see less contact data
_ctx_extra contains f if {
    not _in_working_hours
    {"care_l1", "care_l2", "billing_agent"}[input.role]
    f := {"email", "address"}[_]
}

# Agent-initiated: care_l2 must not see MSISDN when agent pulled the record
_ctx_extra contains "msisdn" if {
    _initiated_by == "agent"
    input.role == "care_l2"
}

# IVR channel: voice routing only needs MSISDN — mask name for agent role
_ctx_extra contains "name" if {
    _channel == "ivr"
    input.role == "agent"
}

# Read-only session: protect financial fields for billing and care_l2
_ctx_extra contains f if {
    _session_type == "readonly"
    {"billing_agent", "care_l2"}[input.role]
    f := {"account_balance", "bill_amount"}[_]
}

# ── Effective masked fields (role baseline + context extras − token unlocks) ──

_role_masked contains f if {
    f := role_masked_fields[input.role][_]
}

_effective_masked contains f if {
    _role_masked[f]
    not _token_unmasked[f]
}

_effective_masked contains f if {
    _ctx_extra[f]
    not _token_unmasked[f]
}

# ── Masked fields ─────────────────────────────────────────────────────────────

masked_fields := [] if {
    startswith(input.path, "/api/unmask")
} else := [f | _effective_masked[f]]

# ── Decision entry point ──────────────────────────────────────────────────────

decision := {
    "allow":          allow,
    "is_vip":         is_vip,
    "customer_tier":  customer_tier,
    "masked_fields":  masked_fields,
    "backend_fields": backend_fields,
}
