package com.example.security_log_system.dto;

import java.time.LocalDateTime;
import java.util.Map;

// 공통 에러 DTO

public record ErrorResponseDto(
        int status,
        String message,
        Map<String,String> errors,
        LocalDateTime timestamp
) {
}
