package com.example.security_log_system.dto;

import java.time.OffsetDateTime;
import java.util.List;

public record RequestAlertMessage(
        String alertId,
        String eventType,   // CREATED(최초 알림), UPDATED(기존 알림의 출처·위험도 변경)
        long revision,
        String ip,
        String type,
        int level,
        OffsetDateTime time,
        List<String> sources
) { }
