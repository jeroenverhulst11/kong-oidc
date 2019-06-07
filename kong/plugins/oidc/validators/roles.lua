local function table_to_string(tbl)
    local result = ""
    for k, v in pairs(tbl) do
        -- Check the key type (ignore any numerical keys - assume its an array)
        if type(k) == "string" then
            result = result.."[\""..k.."\"]".."="
        end

        -- Check the value type
        if type(v) == "table" then
            result = result..table_to_string(v)
        elseif type(v) == "boolean" then
            result = result..tostring(v)
        else
            if result ~= "" then
                result = result .. " " .. v
            else
                result = result .. v
            end
        end
        result = result..","
    end
    -- Remove leading commas from the result
    if result ~= "" then
        result = result:sub(1, result:len()-1)
    end
    return result
end


local function validate_client_roles(oidcConfig, jwt_claims)
    local claim_roles = {}
    if jwt_claims and jwt_claims.resource_access then
        for claim_client, claim_client_roles in pairs(jwt_claims.resource_access) do
            if oidcConfig.client_id == claim_client then
                for _, curr_claim_client_roles in pairs(claim_client_roles) do
                    for _, curr_claim_client_role in pairs(curr_claim_client_roles) do
                        table.insert(claim_roles, curr_claim_client_role)
                    end
                end
            end
        end
    end

    local set_header = kong.service.request.set_header
    local allowed_client_roles = oidcConfig.client_roles
    if allowed_client_roles == nil or table.getn(allowed_client_roles) == 0 then
        -- no verification, set all roles in header
        set_header("X-Client-Roles", table_to_string(claim_roles))
        return true
    end

    -- do verification
    if jwt_claims == nil or jwt_claims.resource_access == nil then
        return nil, "Missing required resource_access claim"
    end

    local roles = {}

    for _, curr_allowed_role in pairs(allowed_client_roles) do
        for _, curr_claim_client_role in pairs(claim_roles) do
            if curr_claim_client_role == curr_allowed_role then
                table.insert(roles, curr_claim_client_role)
            end
        end
    end

    if table.getn(roles) == 0 then
        return nil, "Missing required role"
    else
        set_header("X-Client-Roles", table_to_string(roles))
        return true
    end
end

return {
    validate_client_roles = validate_client_roles
}