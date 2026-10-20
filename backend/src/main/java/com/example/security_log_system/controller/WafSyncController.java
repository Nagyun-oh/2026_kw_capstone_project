package com.example.security_log_system.controller;


import com.example.security_log_system.dto.BlacklistSnapshotDto;
import com.example.security_log_system.service.BlacklistSnapshotService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/waf")
@RequiredArgsConstructor
public class WafSyncController {

    private final BlacklistSnapshotService blacklistSnapshotService;

    @GetMapping("/blacklist")
    public ResponseEntity<BlacklistSnapshotDto> getBlacklist(){
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(blacklistSnapshotService.getSnapshot());
    }
}
