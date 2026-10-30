package com.example.security_log_system.dto;


import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class GroupedThreatResponseDto {

    // 같은 요청의 탐지 중 최초 위협 번호
    private Long id;

    private Long logId;

    // 각 탐지의 실제 위협 번호
    private Long wafThreatId;
    private Long aiThreatId;

    // 백엔드에 먼저 저장된 순서
    private List<String> threatTypes;

    private String severity;

    private String wafDescription;
    private String aiDescription;

    // 기존 HTTP 보조 API 등 다른 유형의 기록 보존
    private String otherDescription;
}
