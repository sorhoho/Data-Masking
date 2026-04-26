package data_masking

# ── Role → masked fields mapping ─────────────────────────────────────────────
#   agent:      sees name, msisdn, email all masked
#   supervisor: sees only msisdn masked
#   admin:      sees everything unmasked
role_masked_fields = {
    "agent":      ["name", "msisdn", "email"],
    "supervisor": ["msisdn"],
    "admin":      []
}

# ── Access decision ───────────────────────────────────────────────────────────
default allow = false

allow {
    input.role == "agent"
}

allow {
    input.role == "supervisor"
}

allow {
    input.role == "admin"
}

# ── Masking fields (empty array = no masking) ─────────────────────────────────
default masked_fields = []

# Unmask endpoint: caller explicitly requested full data; no masking regardless of role
masked_fields = [] {
    startswith(input.path, "/api/unmask")
}

# Regular endpoint: apply role-based masking
masked_fields = fields {
    not startswith(input.path, "/api/unmask")
    fields := role_masked_fields[input.role]
}
