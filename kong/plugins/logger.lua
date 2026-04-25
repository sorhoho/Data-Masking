-- Kong post-function plugin (log phase)
-- Runs AFTER the response is sent to the client – zero latency impact.
-- Reads context left by auth-opa.lua / masking.lua and emits one
-- structured audit event per request to the log dashboard.

local http  = require("resty.http")
local cjson = require("cjson.safe")

local LOG_URL = os.getenv("LOG_DASHBOARD_URL") or "http://log-dashboard:9000/log"

-- ── Gather context ────────────────────────────────────────────────────────
local status      = kong.response.get_status()
local username    = kong.ctx.shared.username      or "anonymous"
local user_role   = kong.ctx.shared.user_role     or "unknown"
local masked      = kong.ctx.shared.masked_fields or {}
local token_ok    = kong.ctx.shared.token_active   -- true | false | nil
local opa_allowed = kong.ctx.shared.opa_allowed    -- true | false | nil
local deny_reason = kong.ctx.shared.deny_reason    -- string | nil

local path        = kong.request.get_path()
local method      = kong.request.get_method()
local customer_id = path:match("/api/customer/([^/?]+)") or ""

-- Derive OPA decision string (fallback from HTTP status when ctx is nil)
local opa_decision
if opa_allowed ~= nil then
    opa_decision = opa_allowed and "ALLOW" or "DENY"
elseif status == 403 then
    opa_decision = "DENY"
elseif status < 400 or status == 404 then
    opa_decision = "ALLOW"
end

-- Level
local level
if    status >= 500 then level = "error"
elseif status >= 400 then level = "warn"
else                      level = "info"
end

-- ── Build and send ────────────────────────────────────────────────────────
local entry = cjson.encode({
    service       = "kong",
    level         = level,
    event         = "api_request",
    method        = method,
    path          = path,
    customer_id   = customer_id,
    http_status   = status,
    user          = username,
    role          = user_role,
    token_active  = token_ok,
    opa_decision  = opa_decision,
    masked_fields = masked,
    masked_count  = #masked,
    deny_reason   = deny_reason,
})

local ok, httpc = pcall(http.new)
if ok then
    httpc:set_timeout(500)
    pcall(function()
        httpc:request_uri(LOG_URL, {
            method  = "POST",
            headers = { ["Content-Type"] = "application/json" },
            body    = entry,
        })
    end)
end
