package com.example.security_log_system.controller;


import com.example.security_log_system.dto.BlacklistSnapshotDto;
import com.example.security_log_system.dto.WafSyncReportDto;
import com.example.security_log_system.service.BlacklistSnapshotService;
import com.example.security_log_system.service.WafSyncStatusService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/internal/waf")
@RequiredArgsConstructor
public class WafSyncController {

    private final BlacklistSnapshotService blacklistSnapshotService;
    private final WafSyncStatusService wafSyncStatusService;

    @GetMapping("/blacklist")
    public ResponseEntity<BlacklistSnapshotDto> getBlacklist(){
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(blacklistSnapshotService.getSnapshot());
    }

    @PostMapping("/sync-status")
    public ResponseEntity<Void> reportStatus(@Valid @RequestBody WafSyncReportDto report){
        wafSyncStatusService.saveReport(report);
        return ResponseEntity.noContent().build();
    }
}
