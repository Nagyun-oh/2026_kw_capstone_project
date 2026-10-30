package com.example.security_log_system.dto;

import java.time.Instant;
import java.util.List;

public record WafSyncStatusDto(
        String wafId,
        DisplayStatus status,
        String currentVersion,
        String attemptedVersion,
        String appliedVersion,
        WafSyncReportDto.SyncResult lastSyncResult,
        List<WafSyncReportDto.ExcludedIp> excludedIps,
        WafSyncReportDto.SyncError error,
        Instant receivedAt,         // 마지막 보고 수신 시각
        Instant checkedAt,          // 조회에서 상태를 계산한 시각
        /*
         * stale 마지막 WAF 보고가 오래돼서 현재 상태를 판단하는 근거로 쓰기 어려운지 나타내는 값
         * 기준은 마지막 보고를 받은 뒤 60초 초과
            - false : 최근 보고이므로 version·성공 여부로 상태 판단
            - true : 보고가 오래됐거나 없어서 UNKNOWN으로 표시
        * */
        boolean stale,
        long staleAfterSeconds

) {
    public enum DisplayStatus{
        APPLIED,            // 적용 확인
        PENDING,            // 반영 대기
        FAILED,             // 동기화 실패
        UNKNOWN             // 상태 미확인
    }
}
