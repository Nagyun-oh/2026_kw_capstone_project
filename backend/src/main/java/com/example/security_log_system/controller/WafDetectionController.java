package com.example.security_log_system.controller;


import com.example.security_log_system.dto.WafDetectionDetailDto;
import com.example.security_log_system.service.WafDetectionQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

// 상세 조회 컨트롤러
/*
응답 기준:
    연결된 WAF 상세가 있음 -> 200
    없는 위협 번호 또는 WAF 상세가 없음 -> 404
    로그인하지 않음 -> 401
    저장된 규칙 JSON이 손상됨 -> 500
 */
@RestController
@RequestMapping("/api/v1/threats")
@RequiredArgsConstructor
public class WafDetectionController {

    private final WafDetectionQueryService wafDetectionQueryService;

    @GetMapping("/{threatId}/waf-detail")
    public ResponseEntity<WafDetectionDetailDto> getWafDetail(
            @PathVariable("threatId") Long threatId
    ){
        return ResponseEntity.of(wafDetectionQueryService.getDetail(threatId));
    }
}

