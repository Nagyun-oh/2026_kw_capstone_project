-- Send one minimal event per request with matched WAF rules.
-- Do not forward audit request/response bodies, headers, or query strings.
function extract_detection(tag, timestamp, record)
    local tx = record.transaction
    if type(tx) ~= "table" or type(tx.messages) ~= "table" then
        return -1, timestamp, record
    end

    local rules = {}
    local score
    for _, message in ipairs(tx.messages) do
        local details = message.details or {}
        local id = tostring(details.ruleId or "")
        if id == "949110" or id == "959100" then
            score = tonumber((message.message or ""):match("Total Score: (%d+)")) or score
        elseif id ~= "" then
            local types = {}
            for _, rule_tag in ipairs(details.tags or {}) do
                if type(rule_tag) == "string" and rule_tag:match("^attack%-") then
                    types[#types + 1] = rule_tag
                end
            end
            rules[#rules + 1] = {
                id = id,
                message = message.message,
                severity = details.severity,
                matched_variable = type(details.match) == "string"
                    and details.match:match("against variable `([^']+)'") or nil,
                attack_types = types
            }
        end
    end
    if #rules == 0 then
        return -1, timestamp, record
    end

    local request = tx.request or {}
    local response = tx.response or {}
    local path = tostring(request.uri or ""):match("^[^?]*")
    return 1, timestamp, {
        source = "waf",
        event_type = "waf_detection",
        request_id = tx.unique_id,
        time = tx.time_stamp,
        client_ip = tx.client_ip,
        method = request.method,
        path = path,
        status = response.http_code,
        anomaly_score = score,
        matched_rules = rules
    }
end
