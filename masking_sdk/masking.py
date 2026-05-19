"""
Masking functions — ported from kong/kong.yml Lua implementation.
Identical behaviour: same inputs produce same outputs as Kong post-filter.
"""
import re


def mask_email(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "***"
    m = re.match(r"^([^@]+)@(.+)$", v)
    if not m:
        return "***"
    user, domain = m.group(1), m.group(2)
    if len(user) <= 2:
        return "*" * len(user) + "@" + domain
    return user[0] + "*" * (len(user) - 2) + user[-1] + "@" + domain


def mask_msisdn(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "***"
    m = re.match(r"^(\+\d{1,2})(\d+)$", v)
    if m:
        prefix, digits = m.group(1), m.group(2)
        if len(digits) <= 2:
            return prefix + "*" * len(digits)
        return prefix + "*" * (len(digits) - 2) + digits[-2:]
    if len(v) <= 4:
        return "*" * len(v)
    return v[:3] + "*" * (len(v) - 5) + v[-2:]


def mask_name(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "***"
    parts = []
    for word in v.split():
        if len(word) <= 1:
            parts.append(word)
        else:
            parts.append(word[0] + "*" * (len(word) - 1))
    return " ".join(parts)


def mask_national_id(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "***"
    if len(v) <= 2:
        return "*" * len(v)
    return v[:2] + "*" * (len(v) - 2)


def mask_address(v: str) -> str:
    if not isinstance(v, str) or not v:
        return "***"
    return "*** (redacted)"


def mask_redact(v) -> str:
    return "***"


MASKERS = {
    "email":              mask_email,
    "msisdn":             mask_msisdn,
    "name":               mask_name,
    "national_id":        mask_national_id,
    "address":            mask_address,
    "last_call_duration": mask_redact,
    "data_roaming_gb":    mask_redact,
    "last_location":      mask_redact,
}


def apply_masking(record: dict, masked_fields: list) -> dict:
    """Return copy of record with masked_fields obfuscated."""
    out = dict(record)
    for field in masked_fields:
        if field in out and out[field] is not None:
            masker = MASKERS.get(field, mask_redact)
            out[field] = masker(str(out[field]))
    return out
