package com.example.security_log_system.repository;

import com.example.security_log_system.entity.WafSyncStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;

public interface WafSyncStatusRepository extends JpaRepository<WafSyncStatus,String> {

    @Modifying
    @Query(value = """
        INSERT INTO waf_sync_status (
            waf_id,
            report_json,
            received_at
        )
        VALUES (
            :wafId,
            :reportJson,
            :receivedAt
        )
        ON DUPLICATE KEY UPDATE
            report_json = :reportJson,
            received_at = :receivedAt
        """,nativeQuery = true)
    void upsert(
            @Param("wafId") String wafId,
            @Param("reportJson") String reportJson,
            @Param("receivedAt") LocalDateTime receivedAt
    );
}
/*
    첫 보고 → INSERT
    같은 wafId의 다음 보고 → UPDATE
*/
