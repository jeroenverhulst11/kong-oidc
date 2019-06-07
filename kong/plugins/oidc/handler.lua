local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local restySession = require("resty.session")
local constants = require "kong.constants"
local validate_client_roles = require("kong.plugins.oidc.validators.roles").validate_client_roles
local keycloak_keys = require("kong.plugins.oidc.keycloak_keys")
local re_gmatch = ngx.re.gmatch

OidcHandler.PRIORITY = 1006

function OidcHandler:new()
    OidcHandler.super.new(self, "oidc")
end

local function set_consumer(consumer, credential, token)
    local set_header = kong.service.request.set_header
    local clear_header = kong.service.request.clear_header

    if consumer and consumer.id then
        set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
    else
        clear_header(constants.HEADERS.CONSUMER_ID)
    end

    if consumer and consumer.custom_id then
        set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
    else
        clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
    end

    if consumer and consumer.username then
        set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
    else
        clear_header(constants.HEADERS.CONSUMER_USERNAME)
    end

    kong.client.authenticate(consumer, credential)

    if credential then
        kong.ctx.shared.authenticated_jwt_token = token -- TODO: wrap in a PDK function?
        ngx.ctx.authenticated_jwt_token = token -- backward compatibilty only

        if credential.username then
            set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
        else
            clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        end

        clear_header(constants.HEADERS.ANONYMOUS)

    else
        clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
        set_header(constants.HEADERS.ANONYMOUS, true)
    end
end

local function load_consumer(consumer_id, anonymous)
    local result, err = kong.db.consumers:select { id = consumer_id }
    if not result then
        if anonymous and not err then
            err = 'anonymous consumer "' .. consumer_id .. '" not found'
        end
        return nil, err
    end
    return result
end

local function handle_unauthenticated(oidcConfig, err)
    if not (oidcConfig.anonymous == nil or oidcConfig.anonymous == "") then
        local consumer_cache_key = kong.db.consumers:cache_key(oidcConfig.anonymous)
        local consumer, err = kong.cache:get(consumer_cache_key, nil,
            load_consumer,
            oidcConfig.anonymous, true)
        if err then
            kong.log.err(err)
            return kong.response.exit(500, { message = "An unexpected error occurred" })
        end
        set_consumer(consumer, nil, nil)
    else
        if oidcConfig.recovery_page_path then
            kong.log.debug("Entering recovery page: " .. oidcConfig.recovery_page_path)
            ngx.redirect(oidcConfig.recovery_page_path)
        end
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
    end
end

local function retrieve_access_token(oidcConfig)
    local authorization_header = kong.request.get_header(oidcConfig.access_token_header_name)
    if authorization_header then
        local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
        if not iterator then
            return nil, iter_err
        end

        local m, err = iterator()
        if err then
            return nil, err
        end

        if m and #m > 0 then
            return m[1]
        end
    end
end

local function get_keys(discovery)
    kong.log.debug('Getting public keys from keycloak')
    keys, err = keycloak_keys.get_issuer_keys(discovery)
    if err then
        return nil, err
    end

    decoded_keys = {}
    for i, key in ipairs(keys) do
        decoded_keys[i] = jwt_decoder:base64_decode(key)
    end

    kong.log.debug('Number of keys retrieved: ' .. table.getn(decoded_keys))
    return {
        keys = decoded_keys,
        updated_at = socket.gettime(),
    }
end

local function validate_signature(oidcConf, jwt, second_call)
    local issuer_cache_key = 'issuer_keys_' .. jwt.claims.iss

    discovery = keycloak_keys.get_wellknown_endpoint(oidcConf.discovery, jwt.claims.iss)
    -- Retrieve public keys
    local public_keys, err = kong.cache:get(issuer_cache_key, nil, get_keys, discovery, true)

    if not public_keys then
        if err then
            kong.log.err(err)
        end
        return kong.response.exit(403, { message = "Unable to get public key for issuer" })
    end

    if jwt.header.alg ~= ("RS256" or "HS256") then
        return false, {status = 403, message = "Invalid algorithm"}
    end

    local ok_claims, errors = jwt:verify_registered_claims({"exp", "nbf"})
    if not ok_claims then
        return false, { status = 401, message = "Token claims invalid: " .. table_to_string(errors) }
    end

    -- Verify signatures
    for _, k in ipairs(public_keys.keys) do
        if jwt:verify_signature(k) then
            kong.log.debug('JWT signature verified')
            return nil
        end
    end

    -- We could not validate signature, try to get a new keyset?
    since_last_update = socket.gettime() - public_keys.updated_at
    if not second_call and since_last_update > oidcConf.iss_key_grace_period then
        kong.log.debug('Could not validate signature. Keys updated last ' .. since_last_update .. ' seconds ago')
        kong.cache:invalidate_local(issuer_cache_key)
        return validate_signature(oidcConf, jwt, true)
    end

    return kong.response.exit(401, { message = "Invalid token signature" })
end

function verify_access_token(oidcConfig)
    local token, err = retrieve_access_token(oidcConfig)
    if err then
        kong.log.err(err)
        return kong.response.exit(500, { message = "An unexpected error occurred" })
    end

    -- Decode token
    local jwt, err = jwt_decoder:new(token)
    if err then
        return false, "Bad token; " .. tostring(err)
    end

    err = validate_signature(oidcConfig, jwt)
    if err ~= nil then
        return false, err
    end

    if oidcConfig.client_roles and not validate_client_roles(oidcConfig.client_roles, jwt.claims) then
        return false, "Access token does not have the required scope/role"
    end

    return true
end

function handle(oidcConfig)
    local response
    if oidcConfig.introspection_endpoint then
        response = introspect(oidcConfig)
        if response then
            utils.injectUser(response, oidcConfig.userinfo_header_name)
        end
    end

    if response == nil then
        response = make_oidc(oidcConfig)
        if response then
            if (not oidcConfig.disable_userinfo_header
                    and response.user) then
                utils.injectUser(response.user, oidcConfig.userinfo_header_name)
            end
            if (not oidcConfig.disable_access_token_header
                    and response.access_token) then
                utils.injectAccessToken(response.access_token, oidcConfig.access_token_header_name, oidcConfig.access_token_as_bearer)
            end
            if (not oidcConfig.disable_id_token_header
                    and response.id_token) then
                utils.injectIDToken(response.id_token, oidcConfig.id_token_header_name)
            end
        end
    end
end

function make_oidc(oidcConfig)
    local res, err
    kong.log.debug("OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)

    local session = restySession.open(oidcConfig);
    if oidcConfig.bearer_only == "yes" and not utils.has_bearer_access_token() and not session.present then
        err = "No Bearer Authorization header or valid session found.";
        kong.log.warn(err)
    end
    if not err then
        res, err = require("resty.openidc").authenticate(oidcConfig)
    end
    if err then
        handle_unauthenticated(oidcConfig, err);
    end
    return res
end

function introspect(oidcConfig)
    if (utils.has_bearer_access_token() and oidcConfig.introspection_endpoint) then
        local res, err = require("resty.openidc").introspect(oidcConfig)
        if err then
            if oidcConfig.bearer_only == "yes" then
                handle_unauthenticated(oidcConfig, err);
            end
            return nil
        end
        kong.log.debug("OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
        return res
    end
    kong.log.debug("Ignoring introspect: no bearer token and introspect url set.")

    return nil
end

function OidcHandler:access(config)
    OidcHandler.super.access(self)

    local oidcConfig = utils.get_options(config, ngx)

    if (ngx.ctx.authenticated_credential and not (oidcConfig.anonymous == nil or oidcConfig.anonymous == "")) then
        -- we're already authenticated, and we're configured for using anonymous,
        -- hence we're in a logical OR between auth methods and we're already done.
        return
    end

    if filter.shouldProcessRequest(oidcConfig) then
        session.configure(config)
        handle(oidcConfig)

        if(config.application_type == "resource") then
            local ok, err = verify_access_token(oidcConfig);
            if not ok then
                handle_unauthenticated(oidcConfig, err)
            end
        end
    else
        kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
    end

    kong.log.debug("OidcHandler done")
end

return OidcHandler
