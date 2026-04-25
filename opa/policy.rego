package data_masking

import rego.v1

# ── Role → masked fields mapping ─────────────────────────────────────────────
#   agent:      sees name, msisdn, email all masked
#   supervisor: sees only msisdn masked
#   admin:      sees everything unmasked
role_masked_fields := {
	"agent":      ["name", "msisdn", "email"],
	"supervisor": ["msisdn"],
	"admin":      [],
}

# ── Access decision ───────────────────────────────────────────────────────────
default allow := false

allow if {input.role == "agent"}

allow if {input.role == "supervisor"}

allow if {input.role == "admin"}

# ── Masking fields (empty array = no masking) ─────────────────────────────────
default masked_fields := []

masked_fields := fields if {
	fields := role_masked_fields[input.role]
}
