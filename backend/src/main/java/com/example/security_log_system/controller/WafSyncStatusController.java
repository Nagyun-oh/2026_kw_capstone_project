package com.example.security_log_system.controller;


import com.example.security_log_system.dto.WafSyncStatusDto;
import com.example.security_log_system.service.WafSyncStatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/* WAF용 관리자 조회 Controller */
@RestController
@RequestMapping("/api/v1/waf")
@RequiredArgsConstructor
public class WafSyncStatusController {

    private final WafSyncStatusService wafSyncStatusService;

    @GetMapping("/sync-status")
    public ResponseEntity<WafSyncStatusDto> getStatus(){
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(wafSyncStatusService.getStatus());
    }


}
