local typedefs = require "kong.db.schema.typedefs"

return {
    name = "oidc",
    fields = {
        {
            consumer = typedefs.no_consumer
        },
        {
            run_on = typedefs.run_on_first
        },
        {
            protocols = typedefs.protocols_http
        },
        {
            config = {
                type = "record",
                fields = {
                    {
                        application_type = {
                            type = "string",
                            required = true,
                            one_of = {
                                "client",
                                "resource"
                            },
                        },
                    },
                    {
                        server = {
                            type = "string",
                            required = true,
                        },
                    },
                    {
                        client_id = {
                            type = "string",
                            required = true,
                        },
                    },
                    {
                        client_secret = {
                            type = "string",
                            required = true,
                        },
                    },
                    {   roles_to_check_if_resource = {
                            type = "set",
                            elements = {
                                type = "string"
                            },
                            default = nil
                        },
                    },
                    {
                        anonymous = {
                            type = "string",
                            uuid = true,
                            legacy = true,
                        },
                    },
                },
            },
        },
    },
}

--return {
--    no_consumer = true,
--    fields = {
--        anonymous = { type = "string", required = false, default = "" },
--        client_id = { type = "string", required = true },
--        client_secret = { type = "string", required = true },
--        discovery = { type = "string", required = true, default = "https://.well-known/openid-configuration" },
--        introspection_endpoint = { type = "string", required = false },
--        timeout = { type = "number", required = false },
--        introspection_endpoint_auth_method = { type = "string", required = false },
--        bearer_only = { type = "string", required = true, default = "no" },
--        realm = { type = "string", required = true, default = "kong" },
--        redirect_uri_path = { type = "string" },
--        scope = { type = "string", required = true, default = "openid" },
--        response_type = { type = "string", required = true, default = "code" },
--        ssl_verify = { type = "string", required = true, default = "no" },
--        token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" },
--        session_secret = { type = "string", required = false },
--        recovery_page_path = { type = "string" },
--        logout_path = { type = "string", required = false, default = '/logout' },
--        redirect_after_logout_uri = { type = "string", required = false, default = '/' },
--        filters = { type = "string" },
--        ignore_auth_filters = { type = "string", default = "" },
--        userinfo_header_name = { type = "string", required = false, default = "X-USERINFO" },
--        id_token_header_name = { type = "string", required = false, default = "X-ID-Token" },
--        access_token_header_name = { type = "string", required = false, default = "X-Access-Token" },
--        access_token_header_as_bearer = { type = "string", required = false, default = "no" },
--        disable_userinfo_header = { type = "string", required = false, default = "no" },
--        disable_id_token_header = { type = "string", required = false, default = "no" },
--        disable_access_token_header = { type = "string", required = false, default = "no" },
--        revoke_tokens_on_logout = { type = "string", required = false, default = "no" }
--    }
--}
