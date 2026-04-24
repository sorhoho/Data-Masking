-- Kong post-function plugin (body_filter phase)
-- Buffers the upstream JSON response and applies field-level masking
-- according to the rules stored by auth-opa.lua in kong.ctx.shared.

local cjson = require("cjson.safe")

-- ── Masking helpers ───────────────────────────────────────────────────────

local function mask_email(v)
    if type(v) ~= "string" or #v == 0 then return "***" end
    local user, domain = v:match("^([^@]+)@(.+)$")
    if not user then return "***" end
    -- keep first char + last char of local-part, mask the middle
    local visible = (function()
        if #user <= 2 then return 1 else return 1 end
    end)()
    return user:sub(1, visible) .. string.rep("*", math.max(0, #user - 2)) .. user:sub(-1) .. "@" .. domain
end

local function mask_msisdn(v)
    if type(v) ~= "string" or #v == 0 then return "***" end
    -- keep leading +CC (up to 3 chars) and last 2 digits
    local prefix, digits = v:match("^(%+%d%d?)(%d+)$")
    if prefix and digits then
        if #digits <= 2 then
            return prefix .. string.rep("*", #digits)
        end
        return prefix .. string.rep("*", #digits - 2) .. digits:sub(-2)
    end
    if #v <= 4 then return string.rep("*", #v) end
    return v:sub(1, 3) .. string.rep("*", #v - 5) .. v:sub(-2)
end

local function mask_name(v)
    if type(v) ~= "string" or #v == 0 then return "***" end
    local parts = {}
    for word in v:gmatch("%S+") do
        if #word <= 1 then
            table.insert(parts, word)
        else
            table.insert(parts, word:sub(1, 1) .. string.rep("*", #word - 1))
        end
    end
    return table.concat(parts, " ")
end

local MASKERS = {
    email  = mask_email,
    msisdn = mask_msisdn,
    name   = mask_name,
}

-- ── Body-filter phase ─────────────────────────────────────────────────────

local masked_fields = kong.ctx.shared.masked_fields

-- Nothing to mask — let Kong stream the body unmodified
if not masked_fields or #masked_fields == 0 then
    return
end

local chunk = ngx.arg[1]
local eof   = ngx.arg[2]

-- Accumulate chunks; suppress them until EOF
kong.ctx.shared.resp_buf = (kong.ctx.shared.resp_buf or "") .. (chunk or "")
ngx.arg[1] = ""

if not eof then
    return
end

-- Process complete body ────────────────────────────────────────────────────
local body = kong.ctx.shared.resp_buf
local data, err = cjson.decode(body)

if not data or err then
    -- Not JSON (e.g. error page from upstream) — pass through unchanged
    ngx.arg[1] = body
    return
end

-- Build lookup set
local to_mask = {}
for _, f in ipairs(masked_fields) do
    to_mask[f] = true
end

-- Apply masking
for field, fn in pairs(MASKERS) do
    if to_mask[field] and data[field] ~= nil then
        data[field] = fn(tostring(data[field]))
    end
end

-- Annotate response so the UI can explain what was masked
data["_masking"] = {
    applied       = true,
    role          = kong.ctx.shared.user_role or "unknown",
    masked_fields = masked_fields,
    gateway       = "kong-opa",
}

local out, enc_err = cjson.encode(data)
if not out then
    kong.log.err("Failed to re-encode masked body: ", enc_err)
    ngx.arg[1] = body  -- fall back to unmasked on encode error
    return
end

ngx.arg[1] = out
