package com.example.security_log_system.service;

import com.example.security_log_system.dto.WafSyncReportDto;
import com.example.security_log_system.dto.WafSyncStatusDto;
import com.example.security_log_system.entity.WafSyncStatus;
import com.example.security_log_system.repository.WafSyncStatusRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Service
public class WafSyncStatusService {

    private final WafSyncStatusRepository repository;
    private final BlacklistSnapshotService snapshotService;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final String expectedWafId;
    private final long staleAfterSeconds;

    public WafSyncStatusService(
            WafSyncStatusRepository repository,
            BlacklistSnapshotService snapshotService,
            ObjectMapper objectMapper,
            @Qualifier("wafSyncClock") Clock clock,
            @Value("${app.waf-sync.expected-waf-id:local-waf-1}")
            String expectedWafId,
            @Value("${app.waf-sync.stale-after-seconds:60}")
            long staleAfterSeconds
    ) {
        if (!expectedWafId.matches("[a-z0-9._-]{1,64}")) {
            throw new IllegalArgumentException(
                    "Invalid expected WAF ID"
            );
        }

        if (staleAfterSeconds < 1) {
            throw new IllegalArgumentException(
                    "WAF status timeout must be positive"
            );
        }

        this.repository = repository;
        this.snapshotService = snapshotService;
        this.objectMapper = objectMapper;
        this.clock = clock;
        this.expectedWafId = expectedWafId;
        this.staleAfterSeconds = staleAfterSeconds;
    }

    @Transactional
    public void saveReport(WafSyncReportDto report) {
        if (!expectedWafId.equals(report.wafId())) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "Unexpected WAF ID"
            );
        }

        String reportJson = serialize(report);

        LocalDateTime receivedAt = LocalDateTime.ofInstant(
                clock.instant(),
                ZoneOffset.UTC
        );

        repository.upsert(
                report.wafId(),
                reportJson,
                receivedAt
        );
    }

    @Transactional(readOnly = true)
    public WafSyncStatusDto getStatus() {
        String currentVersion =
                snapshotService.getSnapshot().version();

        WafSyncStatus stored = repository
                .findById(expectedWafId)
                .orElse(null);

        Instant now = clock.instant();

        if (stored == null) {
            return new WafSyncStatusDto(
                    expectedWafId,
                    WafSyncStatusDto.DisplayStatus.UNKNOWN,
                    currentVersion,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null,
                    now,
                    true,
                    staleAfterSeconds
            );
        }

        WafSyncReportDto report =
                deserialize(stored.getReportJson());

        Instant receivedAt =
                stored.getReceivedAt().toInstant(ZoneOffset.UTC);

        // 60초 "초과" 시 오래된 보고로 판단한다.
        // 미래 시각도 시계 이상으로 보고 미확인 처리한다.
        boolean stale =
                receivedAt.isAfter(now)
                        || now.isAfter(
                        receivedAt.plusSeconds(staleAfterSeconds)
                );

        WafSyncStatusDto.DisplayStatus status =
                calculateStatus(report, currentVersion, stale);

        return new WafSyncStatusDto(
                expectedWafId,
                status,
                currentVersion,
                report.attemptedVersion(),
                report.appliedVersion(),
                report.lastSyncResult(),
                report.excludedIps(),
                report.error(),
                receivedAt,
                now,
                stale,
                staleAfterSeconds
        );
    }

    private WafSyncStatusDto.DisplayStatus calculateStatus(
            WafSyncReportDto report,
            String currentVersion,
            boolean stale
    ) {
        if (stale) {
            return WafSyncStatusDto.DisplayStatus.UNKNOWN;
        }

        if (report.lastSyncResult()
                == WafSyncReportDto.SyncResult.FAILURE) {
            return WafSyncStatusDto.DisplayStatus.FAILED;
        }

        if (report.lastSyncResult()
                == WafSyncReportDto.SyncResult.UNKNOWN
                || report.appliedVersion() == null) {
            return WafSyncStatusDto.DisplayStatus.UNKNOWN;
        }

        if (currentVersion.equals(report.appliedVersion())) {
            return WafSyncStatusDto.DisplayStatus.APPLIED;
        }

        return WafSyncStatusDto.DisplayStatus.PENDING;
    }

    private String serialize(WafSyncReportDto report) {
        try {
            return objectMapper.writeValueAsString(report);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException(
                    "Failed to serialize WAF status report",
                    exception
            );
        }
    }

    private WafSyncReportDto deserialize(String reportJson) {
        try {
            return objectMapper.readValue(
                    reportJson,
                    WafSyncReportDto.class
            );
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException(
                    "Failed to read stored WAF status report",
                    exception
            );
        }
    }
}

/*
- 현재 DB version은 보고를 받을 때가 아니라 조회할 때 계산한다
    WAF가 A 적용 성공 보고
    → 관리자가 블랙리스트 변경, DB version은 B
    → 아직 새 보고가 없어도 조회 결과는 PENDING

- 실패 보고가 오면 이전 성공 JSON 전체를 새 보고로 교체한다.
*/
