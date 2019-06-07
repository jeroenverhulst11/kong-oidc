local function validate_client_roles(oidcConfig, jwt_claims)
    local allowed_client_roles = oidcConfig.client_roles
    local curr_allowed_client = oidcConfig.client_id
    if allowed_client_roles == nil or table.getn(allowed_client_roles) == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.resource_access == nil then
        return nil, "Missing required resource_access claim"
    end

    local roles = {}

    for _, curr_allowed_role in pairs(allowed_client_roles) do
        for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
            if curr_allowed_client == claim_client then
                for _, curr_claim_client_roles in pairs(claim_client_roles) do
                    for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
                        if curr_claim_client_role == curr_allowed_role then
                            table.insert(roles, curr_claim_client_role)
                            return true
                        end
                    end
                end
            end
        end
    end

    if table.getn(roles) == 0 then
        return nil, "Missing required role"
    else
        local set_header = kong.service.request.set_header
        set_header("X-Client-Roles", roles)
        return true
    end
end

return {
    validate_client_roles = validate_client_roles
}