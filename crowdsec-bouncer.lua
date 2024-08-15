local core = require("apisix.core")
local config_local = require("apisix.core.config_local")
local timers = require("apisix.timers")
local ipmatcher = require("resty.ipmatcher")
local ngx = ngx
local ngx_timer_at = ngx.timer.at
local ngx_worker_id = ngx.worker.id
local plugin_name = "crowdsec-bouncer"
local lrucache = core.lrucache.new({
    ttl = 3600,
    count = 1000
})
local crowdsec_bouncer_cache = ngx.shared["plugin-" .. plugin_name]

if not crowdsec_bouncer_cache then
    error("custom_lua_shared_dict \"plugin-crowdsec-bouncer\" not configured")
end

local schema = {
    type = "object",
}

local metadata_schema = {
    type = "object",
    properties = {
        crowdsec_lapi_scheme = { type = "string", enum = { "http", "https" }, default = "http" },
        crowdsec_lapi_url = { type = "string", minLength = 1 },
        crowdsec_lapi_port = { type = "integer", minimum = 1, maximum = 65535, default = 8080 },
        crowdsec_lapi_key = { type = "string" },
        update_interval = { type = "integer", minimum = 1, default = 300 },
        ssl_verify = { type = "boolean", default = false },
        whitelist = {
            type = "array",
            items = { type = "string", pattern = "^([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?$" },
            default = {}
        }
    },
    required = { "crowdsec_lapi_scheme", "crowdsec_lapi_url", "crowdsec_lapi_key" }
}

local _M = {
    version = 0.1,
    priority = 25,
    name = plugin_name,
    schema = schema,
}

local function get_client_ip(ctx)
    return ctx.var.remote_addr
end

local whitelist_matcher

local function fetch_crowdsec_data(conf)
    core.log.info("Fetching CrowdSec data")

    local httpc = require("resty.http").new()
    httpc:set_timeout(10000)
    local uri = conf.crowdsec_lapi_scheme ..
        "://" .. conf.crowdsec_lapi_url .. ":" .. conf.crowdsec_lapi_port .. "/v1/decisions/stream?startup=true"

    local res, err
    local retries = 3
    for i = 1, retries do
        res, err = httpc:request_uri(uri, {
            method = "GET",
            headers = {
                ["X-API-KEY"] = conf.crowdsec_lapi_key,
                ["User-Agent"] = "apisix-plugin-" .. plugin_name .. "/" .. _M.version
            },
            ssl_verify = conf.ssl_verify
        })

        if res then break end
        core.log.error("Failed to request CrowdSec: ", err, " (Attempt ", i, " of ", retries, ")")
        ngx.sleep(1)
    end

    if not res then
        core.log.error("All retry attempts to fetch CrowdSec decisions failed")
        return nil, err
    end

    local data, decode_err = core.json.decode(res.body)
    if not data then
        core.log.error("Failed to decode response: ", decode_err)
        return nil, decode_err
    end

    core.log.info("Successfully fetched and decoded CrowdSec decisions")
    return data, nil
end

local function process_crowdsec_decisions(data)
    if type(data.new) == "table" then
        for _, decision in ipairs(data.new) do
            local ttl = decision.type == "ban" and 3600 * 24 or 3600
            crowdsec_bouncer_cache:set(decision.value, core.json.encode(decision), ttl)
            lrucache(decision.value, ttl, function() return decision end)
        end
    end

    if type(data.deleted) == "table" then
        for _, decision in ipairs(data.deleted) do
            crowdsec_bouncer_cache:delete(decision.value)
            lrucache(decision.value, nil, function() return nil end)
        end
    end
end

local function fetch_crowdsec_decisions(conf)
    local data, err = fetch_crowdsec_data(conf)
    if not data then return false end
    process_crowdsec_decisions(data)
    return true
end

local function is_whitelisted(ip)
    if not whitelist_matcher then
        return false
    end
    return whitelist_matcher:match(ip) == true
end

function _M.init()
    core.log.info("Initializing CrowdSec Bouncer Plugin")

    local local_conf = config_local.local_conf()
    if not local_conf then
        core.log.error("local_conf is nil")
        return
    end

    local attr = core.table.try_read_attr(local_conf, "plugin_attr", plugin_name)
    if not attr then
        core.log.error("Failed to read plugin attributes")
        return
    end

    local ok, err = core.schema.check(metadata_schema, attr)
    if not ok then
        core.log.error("Failed to check plugin_attr: ", err)
        return
    end

    if attr.whitelist and #attr.whitelist > 0 then
        whitelist_matcher, err = ipmatcher.new(attr.whitelist)
        if not whitelist_matcher then
            core.log.error("Failed to create IP matcher for whitelist: ", err)
            return
        end
    end

    if ngx_worker_id() == 0 then
        local ok, err = ngx_timer_at(0, fetch_decisions_timer, attr)
        if not ok then
            core.log.error("Failed to create initial timer: ", err)
            return
        end
    end
end

function fetch_decisions_timer(premature, attr)
    if premature then
        return
    end

    if not fetch_crowdsec_decisions(attr) then
        core.log.warn("Failed to fetch CrowdSec decisions, will retry in next interval")
    end

    local ok, err = ngx_timer_at(attr.update_interval, fetch_decisions_timer, attr)
    if not ok then
        core.log.error("Failed to create timer: ", err)
    end
end

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_METADATA then
        return core.schema.check(metadata_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

function _M.access(conf, ctx)
    local client_ip = get_client_ip(ctx)

    if is_whitelisted(client_ip) then
        return
    end

    local decision = lrucache(client_ip, nil, function() return nil end)
    if not decision then
        local decision_json = crowdsec_bouncer_cache:get(client_ip)
        if decision_json then
            decision = core.json.decode(decision_json)
            lrucache(client_ip, nil, function() return decision end)
        end
    end

    if decision and decision.type == "ban" then
        core.log.warn("Access forbidden for client IP: ", client_ip)
        ngx.header["Connection"] = "close"
        return 403, { message = "Forbidden by CrowdSec" }
    end
end

function _M.destroy()
    timers.unregister_timer("plugin#crowdsec-bouncer")
    crowdsec_bouncer_cache:flush_all()
    core.log.info("CrowdSec Bouncer Plugin destroyed and cleaned up")
end

return _M
