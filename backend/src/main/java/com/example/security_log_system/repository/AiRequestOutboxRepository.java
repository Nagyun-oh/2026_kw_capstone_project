package com.example.security_log_system.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class AiRequestOutboxRepository {

    private final JdbcTemplate jdbcTemplate;

    public record Candidate(
            long logId,
            String payload,
            long attempts
    ) {
    }

    // 로그 하나당 AI 요청 아웃박스 레코드를 PENDING 상태로 새로 저장 (즉시 처리 가능)
    public void insert(long logId, String payload) {
        jdbcTemplate.update("""
                INSERT INTO ai_request_outbox (
                    log_id,
                    payload,
                    state,
                    attempts,
                    available_at,
                    created_at,
                    updated_at
                )
                VALUES (
                    ?, ?,
                    'PENDING',
                    0,
                    UTC_TIMESTAMP(6),
                    UTC_TIMESTAMP(6),
                    UTC_TIMESTAMP(6)
                )
                """,
                logId,
                payload
        );
    }


    // 처리 가능한 레코드 1건을 행 잠금과 함께 조회 (PENDING 또는 리스가 만료된 IN_FLIGHT, 다른 워커가 잠근 행은 건너뜀)
    public Optional<Candidate> findReadyForUpdate() {
        return jdbcTemplate.query("""
                SELECT log_id, payload, attempts
                FROM ai_request_outbox
                WHERE state IN ('PENDING', 'IN_FLIGHT')
                  AND available_at <= UTC_TIMESTAMP(6)
                ORDER BY available_at, log_id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """,
                (rs, rowNum) -> new Candidate(
                        rs.getLong("log_id"),
                        rs.getString("payload"),
                        rs.getLong("attempts")
                )
        ).stream().findFirst();
    }

    // 조회한 레코드를 IN_FLIGHT로 바꾸고 리스 토큰 발급, 시도 횟수 +1, 60초 리스 설정
    public int claim(long logId, String leaseToken) {
        return jdbcTemplate.update("""
                UPDATE ai_request_outbox
                SET state = 'IN_FLIGHT',
                    lease_token = ?,
                    attempts = attempts + 1,
                    available_at = TIMESTAMPADD(
                        SECOND, 60, UTC_TIMESTAMP(6)
                    ),
                    updated_at = UTC_TIMESTAMP(6)
                WHERE log_id = ?
                """,
                leaseToken,
                logId
        );
    }


    // 리스 토큰이 일치하는 IN_FLIGHT 레코드를 SENT(전송 완료)로 확정
    public int markSent(long logId, String leaseToken) {
        return jdbcTemplate.update("""
                UPDATE ai_request_outbox
                SET state = 'SENT',
                    lease_token = NULL,
                    last_error_code = NULL,
                    published_at = UTC_TIMESTAMP(6),
                    updated_at = UTC_TIMESTAMP(6)
                WHERE log_id = ?
                  AND state = 'IN_FLIGHT'
                  AND lease_token = ?
                """,
                logId,
                leaseToken
        );
    }

    // 리스 토큰이 일치하는 IN_FLIGHT 레코드를 에러 코드와 함께 PENDING으로 되돌리고 delaySeconds 후 재시도 예약
    public int scheduleRetry(
            long logId,
            String leaseToken,
            int delaySeconds,
            String errorCode
    ) {
        return jdbcTemplate.update("""
                UPDATE ai_request_outbox
                SET state = 'PENDING',
                    lease_token = NULL,
                    last_error_code = ?,
                    available_at = TIMESTAMPADD(
                        SECOND, ?, UTC_TIMESTAMP(6)
                    ),
                    updated_at = UTC_TIMESTAMP(6)
                WHERE log_id = ?
                  AND state = 'IN_FLIGHT'
                  AND lease_token = ?
                """,
                errorCode,
                delaySeconds,
                logId,
                leaseToken
        );
    }
}