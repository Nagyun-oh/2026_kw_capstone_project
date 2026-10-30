package com.example.security_log_system.repository;

import com.example.security_log_system.entity.DetectedThreat;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/* 탐지된 위협 데이터를 저장하고 조회하는 용도입니다. */
@Repository
public interface ThreatRepository
        extends JpaRepository<DetectedThreat,Long>,
        JpaSpecificationExecutor<DetectedThreat> {
    boolean existsByLogEntry_IdAndThreatType(Long logId, String threatType);
    Optional<DetectedThreat> findByLogEntry_IdAndThreatType(Long logId,String threatType);

    /**
     * AI·WAF 탐지는 공통 requestId로 묶는다.
     * requestId가 없는 기존 기록은 LogId로 묶고,
     * 둘 다 없으면 개별 탐지로 유지한다.
     */
    String GROUPED_THREATS = """
    WITH grouped AS (
        SELECT
            MIN(t.id) AS id,
            MAX(t.id) AS lastThreatId,
            MAX(n.id) AS logId,

            MAX(
                CASE WHEN t.threat_type = 'WAF Detection'
                     THEN t.id END
            ) AS wafThreatId,

            MAX(
                CASE WHEN t.threat_type = 'AI Detection'
                     THEN t.id END
            ) AS aiThreatId,

            MAX(
                CASE UPPER(t.severity)
                    WHEN 'CRITICAL' THEN 4
                    WHEN 'HIGH' THEN 3
                    WHEN 'MEDIUM' THEN 2
                    WHEN 'LOW' THEN 1
                    ELSE 0
                END
            ) AS severityRank,

            MAX(
                CASE WHEN t.threat_type = 'WAF Detection'
                     THEN t.description END
            ) AS wafDescription,

            MAX(
                CASE WHEN t.threat_type = 'AI Detection'
                     THEN t.description END
            ) AS aiDescription,

            MAX(t.threat_type) AS fallbackType,
            MAX(t.description) AS fallbackDescription,

            MAX(
                CASE
                    WHEN LOWER(t.threat_type) LIKE
                         CONCAT('%', LOWER(:threatType), '%')
                    THEN 1
                    ELSE 0
                END
            ) AS matchesType,
            
            MAX(
                CASE WHEN t.id = :threatId
                    THEN 1
                    ELSE 0
                END
            ) AS matchesThreatId

        FROM detected_threats t

        LEFT JOIN network_logs n
            ON n.id = t.log_id

        LEFT JOIN waf_detections w
            ON w.threat_id = t.id

        GROUP BY
            CASE
                WHEN t.threat_type IN (
                    'AI Detection', 'WAF Detection'
                )
                THEN COALESCE(
                    CONCAT(
                        'request:',
                        CAST(NULLIF(n.request_id, '') AS BINARY)
                    ),
                    CONCAT(
                        'request:',
                        CAST(NULLIF(w.request_id, '') AS BINARY)
                    ),
                    CONCAT('log:', n.id),
                    CONCAT('threat:', t.id)
                )
                ELSE CONCAT('threat:', t.id)
            END
    )
    """;

    // 묶인 요청을 기준으로 검색
    String GROUPED_FILTER = """
    WHERE (
        :source IS NULL
        OR (:source = 'AI' AND aiThreatId IS NOT NULL)
        OR (:source = 'WAF' AND wafThreatId IS NOT NULL)
    )
    AND (
        :severity IS NULL
        OR :severity = CASE severityRank
            WHEN 4 THEN 'CRITICAL'
            WHEN 3 THEN 'HIGH'
            WHEN 2 THEN 'MEDIUM'
            WHEN 1 THEN 'LOW'
            ELSE 'UNKNOWN'
        END
    )
    AND (
        :threatType IS NULL
        OR matchesType = 1
    )
    AND (
        :threatId IS NULL
        OR matchesThreatId = 1
    )
    """;

    // SQL 결과를 Java로 받음
    @Query(
            value = GROUPED_THREATS
                    + " SELECT * FROM grouped "
                    + GROUPED_FILTER
                    + " ORDER BY lastThreatId DESC ",
            countQuery = GROUPED_THREATS
                    + " SELECT COUNT(*) FROM grouped "
                    + GROUPED_FILTER,
            nativeQuery = true
    )
    Page<GroupedThreatRow> findGroupedThreats(
            @Param("source") String source,
            @Param("severity") String severity,
            @Param("threatType") String threatType,
            @Param("threatId") Long threatId,
            Pageable pageable
    );

    // 결과를 받을 형태
    interface GroupedThreatRow {

        Long getId();
        Long getLogId();

        Long getWafThreatId();
        Long getAiThreatId();

        Integer getSeverityRank();

        String getWafDescription();
        String getAiDescription();

        // AI·WAF 이외의 기존 탐지 기록도 유형과 설명을 잃지 않도록 가져오는 값
        String getFallbackType();
        String getFallbackDescription();
    }
}

/*
    탐지 기록 조회:
     → HTTP 로그·WAF 상세 연결
     → requestId 기준 그룹화
     → 출처별 ID·설명과 최고 위험도 추출
     → 그룹 기준 검색
     → 최신순 정렬·페이지 처리
     → Java DTO 변환
     → 대시보드 한 행 표시
 */
