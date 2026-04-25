-- Kong pre-function plugin (access phase)
-- 1. Validate Bearer token with Keycloak introspection
-- 2. Determine user's highest-priority role
-- 3. Call OPA for allow/deny + masking-fields decision
-- 4. Populate kong.ctx.shared for masking.lua and logger.lua

local http  = require("resty.http")
local cjson = require("cjson.safe")

-- On Render, KEYCLOAK_HOST is injected via fromService (e.g. "keycloak-xxxx.onrender.com").
-- Locally (docker-compose) KEYCLOAK_HOST is unset → fall back to the internal HTTP URL.
local keycloak_host = os.getenv("KEYCLOAK_HOST") or ""
local KEYCLOAK_INTROSPECT
if keycloak_host ~= "" then
    KEYCLOAK_INTROSPECT = "https://" .. keycloak_host
        .. "/realms/demo/protocol/openid-connect/token/introspect"
else
    KEYCLOAK_INTROSPECT = os.getenv("KEYCLOAK_INTROSPECT_URL")
        or "http://keycloak:8080/realms/demo/protocol/openid-connect/token/introspect"
end

local KONG_CLIENT_ID     = "kong-client"
local KONG_CLIENT_SECRET = "kong-secret-456"
local OPA_URL            = os.getenv("OPA_URL") or "http://opa:8181/v1/data/data_masking"
local ROLE_PRIORITY      = { admin = 3, supervisor = 2, agent = 1 }

-- Initialise context so logger.lua always has something to read
kong.ctx.shared.token_active = false
kong.ctx.shared.opa_allowed  = false
kong.ctx.shared.deny_reason  = nil

local function json_exit(status, msg)
    return kong.response.exit(status, { error = true, message = msg },
        { ["Content-Type"] = "application/json" })
end

-- ── 1. Extract Bearer token ───────────────────────────────────────────────
local auth_header = kong.request.get_header("Authorization")
if not auth_header then
    kong.ctx.shared.deny_reason = "missing_token"
    return json_exit(401, "Missing Authorization header")
end

local token = auth_header:match("^[Bb]earer%s+(.+)$")
if not token then
    kong.ctx.shared.deny_reason = "malformed_header"
    return json_exit(401, "Invalid Authorization header format")
end

-- ── 2. Introspect token ───────────────────────────────────────────────────
local httpc = http.new()
httpc:set_timeout(8000)

local res, err = httpc:request_uri(KEYCLOAK_INTROSPECT, {
    method     = "POST",
    headers    = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    body       = "token=" .. token
              .. "&client_id=" .. KONG_CLIENT_ID
              .. "&client_secret=" .. KONG_CLIENT_SECRET,
    ssl_verify = (keycloak_host ~= ""),  -- verify TLS on Render; skip for local HTTP
})

if not res then
    kong.log.err("Keycloak introspection network error: ", err)
    kong.ctx.shared.deny_reason = "keycloak_unreachable"
    return json_exit(503, "Authentication service unavailable")
end

if res.status ~= 200 then
    kong.log.err("Keycloak introspection HTTP ", res.status)
    kong.ctx.shared.deny_reason = "keycloak_error"
    return json_exit(503, "Authentication service error")
end

local intro, parse_err = cjson.decode(res.body)
if not intro then
    kong.log.err("Cannot parse Keycloak response: ", parse_err)
    kong.ctx.shared.deny_reason = "keycloak_bad_response"
    return json_exit(503, "Invalid authentication response")
end

kong.ctx.shared.token_active = intro.active == true

if not intro.active then
    kong.ctx.shared.deny_reason = "token_inactive"
    return json_exit(401, "Token is inactive or expired")
end

-- ── 3. Resolve highest-priority role ─────────────────────────────────────
local user_role    = nil
local max_priority = 0
local realm_roles  = (intro.realm_access or {}).roles or {}

for _, r in ipairs(realm_roles) do
    local p = ROLE_PRIORITY[r]
    if p and p > max_priority then
        user_role    = r
        max_priority = p
    end
end

if not user_role then
    kong.log.warn("No valid role for user: ", intro.preferred_username)
    kong.ctx.shared.deny_reason = "no_valid_role"
    return json_exit(403, "Access denied: no valid role assigned")
end

-- ── 4. Call OPA ───────────────────────────────────────────────────────────
local opa_payload = cjson.encode({
    input = {
        role     = user_role,
        username = intro.preferred_username or "unknown",
        path     = kong.request.get_path(),
        method   = kong.request.get_method(),
    }
})

local opa_res, opa_err = httpc:request_uri(OPA_URL, {
    method  = "POST",
    headers = { ["Content-Type"] = "application/json" },
    body    = opa_payload,
})

if not opa_res then
    kong.log.err("OPA request failed: ", opa_err)
    kong.ctx.shared.deny_reason = "opa_unreachable"
    return json_exit(503, "Policy service unavailable")
end

local opa_data, opa_parse_err = cjson.decode(opa_res.body)
if not opa_data then
    kong.log.err("Cannot parse OPA response: ", opa_parse_err)
    kong.ctx.shared.deny_reason = "opa_bad_response"
    return json_exit(503, "Invalid policy response")
end

local policy = opa_data.result or {}

-- ── 5. Enforce decision ───────────────────────────────────────────────────
if not policy.allow then
    kong.log.info("OPA denied: user=", intro.preferred_username, " role=", user_role)
    kong.ctx.shared.deny_reason = "opa_denied"
    return json_exit(403, "Access denied by security policy")
end

-- ── 6. Propagate context for masking.lua and logger.lua ──────────────────
kong.ctx.shared.opa_allowed   = true
kong.ctx.shared.masked_fields = policy.masked_fields or {}
kong.ctx.shared.user_role     = user_role
kong.ctx.shared.username      = intro.preferred_username or "unknown"

kong.log.info(
    "Access granted: user=", intro.preferred_username,
    " role=", user_role,
    " fields_to_mask=", tostring(#(policy.masked_fields or {}))
)
