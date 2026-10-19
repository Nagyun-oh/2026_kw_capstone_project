package com.example.security_log_system.repository;


import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


// 알림 테이블 접근 코드
@Repository
@RequiredArgsConstructor
public class RequestAlertRepository {

    private final JdbcTemplate jdbcTemplate;

    public record AlertState(
            String alertKey,
            String alertId,
            String clientIp,
            boolean wafDetected,
            boolean aiDetected,
            int alertLevel,
            long revision,
            long publishedRevision,
            boolean pending,
            LocalDateTime updatedAt
    ) { }

    // 새 요청이면 행을 생성하고, 중복 키가 잇으면 기존 값을 유지하는 SQL
    public void createIfAbsent(String alertKey, String clientIp){
        jdbcTemplate.update("""
               INSERT INTO request_alerts(
                    alert_key,
                    alert_id,
                    client_ip,
                    created_at,
                    updated_at
               )
               VALUES(?,?,?,UTC_TIMESTAMP(6),UTC_TIMESTAMP(6))
               ON DUPLICATE KEY UPDATE alert_key = alert_key
               """,
                alertKey,
                UUID.randomUUID().toString(),
                clientIp
        );
    }

    // 상태 조회 + 행 잠금
    /*
        조회한 행에 잠금을 걸어서, 같은 행을 변경하려는 다른 트랜잭션이 기다리게 함.
        WAF와 AI 결과가 동시에 들어왔을 때 서로의 변경 내용을 덮어쓰는 문제를 방지하는 데 사용
    * */
    public Optional<AlertState> findForUpdate(String alertKey){
        return jdbcTemplate.query("""
                SELECT *
                FROM request_alerts
                WHERE alert_key = ?
                FOR UPDATE
                """,
                (rs,rowNum) -> new AlertState(
                        rs.getString("alert_key"),
                        rs.getString("alert_id"),
                        rs.getString("client_ip"),
                        rs.getBoolean("waf_detected"),
                        rs.getBoolean("ai_detected"),
                        rs.getInt("alert_level"),
                        rs.getLong("revision"),
                        rs.getLong("published_revision"),
                        rs.getBoolean("pending"),
                        rs.getObject("updated_at", LocalDateTime.class)
                ),
                alertKey
        ).stream().findFirst();
    }

    // 탐지 결과 변경 + 발행 대기
    public void updateDetection(
            String alertKey,
            boolean wafDetected,
            boolean aiDetected,
            int alertLevel
    ){
        jdbcTemplate.update("""
                UPDATE request_alerts
                SET waf_detected = ?,
                    ai_detected = ?,
                    alert_level = ?,
                    revision = revision +1,
                    pending = TRUE,
                    updated_at = UTC_TIMESTAMP(6)
                WHERE alert_key = ?
                """,
                wafDetected,
                aiDetected,
                alertLevel,
                alertKey
        );
    }

    // 발행 대기 목록 조회
    public List<String> findPendingKeys(){
        return jdbcTemplate.queryForList("""
                SELECT alert_key
                FROM request_alerts
                WHERE pending = TRUE
                ORDER BY updated_at, alert_key
                LIMIT 100
                """, String.class
        );
    }

    // 해당 버전의 발행 완료 처리
    public void markPublished(String alertKey, long revision){

        // update()의 반환값은 SQL로 영향을 받은 행 수
        int updated = jdbcTemplate.update("""
                UPDATE request_alerts
                SET published_revision = ?,
                    pending = FALSE
                WHERE alert_key = ?
                    AND revision = ?
                """,
                revision,
                alertKey,
                revision
        );

        if(updated != 1){
            throw new IllegalStateException(
                    "Request alert revision changed unexpectedly"
            );
        }
    }
}
