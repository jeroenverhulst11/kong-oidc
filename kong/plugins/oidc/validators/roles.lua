local function validate_client_roles(allowed_client_roles, jwt_claims)
    if allowed_client_roles == nil or table.getn(allowed_client_roles) == 0 then
        return true
    end

    if jwt_claims == nil or jwt_claims.resource_access == nil then
        return nil, "Missing required resource_access claim"
    end

    for _, allowed_client_role in pairs(allowed_client_roles) do
        for curr_allowed_client, curr_allowed_role in string.gmatch(allowed_client_role, "(%S+):(%S+)") do
            for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
                if curr_allowed_client == claim_client then
                    for _, curr_claim_client_roles in pairs(claim_client_roles) do
                        for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
                            if curr_claim_client_role == curr_allowed_role then
                                return true
                            end
                        end
                    end
                end
            end
        end
    end

    return nil, "Missing required role"
end

return {
    validate_client_roles = validate_client_roles
}