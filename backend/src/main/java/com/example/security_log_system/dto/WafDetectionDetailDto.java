package com.example.security_log_system.dto;

import java.time.OffsetDateTime;
import java.util.List;

// WAF 상세 응답 DTO
public record WafDetectionDetailDto(
        Long id,
        Long threatId,
        Long logId,
        String requestId,
        String threatType,
        String severity,
        String description,
        String clientIp,
        String requestMethod,
        String requestPath,
        Integer responseStatus,
        Integer anomalyScore,
        String eventTimeRaw,
        OffsetDateTime occurredAt,
        OffsetDateTime receivedAt,
        List<Rule> matchedRules
) {
    public record Rule(
            String id,
            String message,
            String severity,
            String matchedVariable,
            List<String> attackTypes
    ){ }
}

