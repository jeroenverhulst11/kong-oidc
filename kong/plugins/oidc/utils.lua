local cjson = require("cjson")

local M = {}

local function parseFilters(csvFilters)
    local filters = {}
    if (not (csvFilters == nil)) and (not (csvFilters == ",")) then
        for pattern in string.gmatch(csvFilters, "[^,]+") do
            table.insert(filters, pattern)
        end
    end
    return filters
end

local function formatAsBearerToken(token)
    return "Bearer " .. token
end

function M.get_redirect_uri(ngx)
    local function drop_query()
        local uri = ngx.var.request_uri
        local x = uri:find("?")
        if x then
            return uri:sub(1, x - 1)
        else
            return uri
        end
    end

    local function tackle_slash(path)
        local args = ngx.req.get_uri_args()
        if args and args.code then
            return path
        elseif path == "/" then
            return "/cb"
        elseif path:sub(-1) == "/" then
            return path:sub(1, -2)
        else
            return path .. "/"
        end
    end

    return tackle_slash(drop_query())
end

function M.get_options(config, ngx)

    local bearer_only_var, introspection_endpoint_var, dicovery_var
    if config.application_type == "client" then bearer_only_var = "no" else bearer_only_var = "yes" end
    dicovery_var = (config.server .. "/auth/realms/" .. config.realm .. "/.well-known/openid-configuration")
    if config.application_type == "client" then introspection_endpoint_var = nil else introspection_endpoint_var = (config.server .. "/auth/realms/" .. config.realm .. "/protocol/openid-connect/token/introspect") end

    return {
        anonymous = config.anonymous,
        client_id = config.client_id,
        client_secret = config.client_secret,
        discovery = dicovery_var,
        introspection_endpoint = introspection_endpoint_var,
        timeout = nil,
        introspection_endpoint_auth_method = nil,
        bearer_only = bearer_only_var,
        realm = config.realm,
        redirect_uri = M.get_redirect_uri(ngx),
        scope = "openid",
        response_type = "code",
        ssl_verify = "no",
        token_endpoint_auth_method = "client_secret_post",
        recovery_page_path = nil,
        filters = parseFilters(","),
        logout_path = "/logout",
        redirect_after_logout_uri = "/",
        userinfo_header_name = "X-USERINFO",
        id_token_header_name = "X-ID-Token",
        access_token_header_name = "Authorization",
        access_token_as_bearer = true,
        disable_userinfo_header = false,
        disable_id_token_header = false,
        disable_access_token_header = false
    }
end

function M.exit(httpStatusCode, message, ngxCode)
    ngx.status = httpStatusCode
    ngx.say(message)
    ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken, headerName, bearerToken)
    ngx.log(ngx.DEBUG, "Injecting " .. headerName)
    token = accessToken
    if (bearerToken) then
        token = formatAsBearerToken(token)
    end
    ngx.req.set_header(headerName, token)
end

function M.injectIDToken(idToken, headerName)
    ngx.log(ngx.DEBUG, "Injecting " .. headerName)
    local tokenStr = cjson.encode(idToken)
    ngx.req.set_header(headerName, ngx.encode_base64(tokenStr))
end

function M.injectUser(user, headerName)
    ngx.log(ngx.DEBUG, "Injecting " .. headerName)
    local tmp_user = user
    tmp_user.id = user.sub
    tmp_user.username = user.preferred_username
    ngx.ctx.authenticated_credential = tmp_user
    local userinfo = cjson.encode(user)
    ngx.req.set_header(headerName, ngx.encode_base64(userinfo))
end

function M.has_bearer_access_token()
    local header = ngx.req.get_headers()['Authorization']
    if header and header:find(" ") then
        local divider = header:find(' ')
        if string.lower(header:sub(0, divider - 1)) == string.lower("Bearer") then
            return true
        end
    end
    return false
end

return M
