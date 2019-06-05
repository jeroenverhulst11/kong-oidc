local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local restySession = require("resty.session")
local constants = require "kong.constants"

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
    OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
    OidcHandler.super.access(self)

    local oidcConfig = utils.get_options(config, ngx)

    if ngx.ctx.authenticated_credential and not (oidcConfig.anonymous == nil or oidcConfig.anonymous == "") then
        -- we're already authenticated, and we're configured for using anonymous,
        -- hence we're in a logical OR between auth methods and we're already done.
        return
    end

    if filter.shouldProcessRequest(oidcConfig) then
        session.configure(config)
        handle(oidcConfig)

    else
        kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
    end

    kong.log.debug("OidcHandler done")
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
    kong.log.debug("Bearer only: " .. tostring(oidcConfig.bearer_only))
    kong.log.debug("Access token: " .. tostring(utils.has_bearer_access_token()))
    kong.log.debug("Existing session: " .. tostring(session.present))
    if oidcConfig.bearer_only == "yes" and not utils.has_bearer_access_token() and not session.present and not oidcConfig.response_type == "token" then
        err = "No Bearer Authorization header or valid session found.";
        kong.log.warn(err)
    end
    if not err then
        if not oidcConfig.response_type == "token" then
            res, err = require("resty.openidc").authenticate(oidcConfig)
        else
            kong.log.warn("Trying to get access token for m2m configuration")
            local access_token
            access_token, err = require("resty.openidc").access_token(oidcConfig)
            if not err then
                kong.log.warn("Access token for m2m configuration: " .. tostring(access_token))
                kong.log.warn("Error getting access token for m2m configuration: " .. tostring(err))
                res = {
                    access_token = access_token
                }
                return res
            end
        end
    end
    if err then
        if not (oidcConfig.anonymous == nil or oidcConfig.anonymous == "") then
            -- get anonymous user
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
    return res
end

function introspect(oidcConfig)
    if (utils.has_bearer_access_token() and oidcConfig.introspection_endpoint) then
        local res, err = require("resty.openidc").introspect(oidcConfig)
        if err then
            if oidcConfig.bearer_only == "yes" then
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
                    ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
                    utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
                end
            end
            return nil
        end
        kong.log.debug("OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
        return res
    end
    kong.log.debug("Ignoring introspect: no bearer token and introspect url set.")

    return nil
end

return OidcHandler
