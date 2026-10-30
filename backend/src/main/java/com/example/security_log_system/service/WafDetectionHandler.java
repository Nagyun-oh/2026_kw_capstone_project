package com.example.security_log_system.service;

import com.example.security_log_system.dto.WafDetectionEventDto;

// Consumer가 검증한 WAF 이벤트를 저장 담당 코드에 전달
public interface WafDetectionHandler {
    void handle(WafDetectionEventDto event);
}
