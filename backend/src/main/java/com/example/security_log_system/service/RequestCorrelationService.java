package com.example.security_log_system.service;


import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.repository.LogRepository;
import com.example.security_log_system.repository.WafDetectionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(propagation = Propagation.MANDATORY)
public class RequestCorrelationService {

    private final JdbcTemplate jdbcTemplate;
    private final LogRepository logRepository;
    private final WafDetectionRepository wafDetectionRepository;

    // 처음이면 행을 생성한다.
    // 이미 있으면 같은 값을 유지하면서 해당 행의 잠금을 획득한다.
    public Optional<LogEntry> lockAndFindLog(String requestId){
        validateRequestId(requestId);

        // 처음이면 행을 생성한다.
        // 이미 있으면 같은 값을 유지하면서 해당 행의 잠금을 획득한다.
        jdbcTemplate.update("""
                 INSERT INTO request_correlations (request_id)
                 VALUES (?)
                 ON DUPLICATE KEY UPDATE request_id = request_id
        """,requestId);

        return logRepository.findByRequestId(requestId);
    }

    // AI 저장 경로에도 잠금·중복·확인·알림 기록 연결
    /*
     AI 결과가 재전달됐을 때 위협을 계속 생성하지 않도록 같은 저장 경로에서 중복 확인
    **/
    public void lockForAiResult(LogEntry entry){
        if(entry.getRequestId() !=null){
            lockAndFindLog(entry.getRequestId());
            return;
        }

        // requestId가 없는 과거 로그는 원본 로그 행으로 직렬화한다.
        jdbcTemplate.queryForObject("""
            SELECT id
            FROM network_logs
            WHERE id = ?
            FOR UPDATE
            """,
                Long.class,
                entry.getId()
        );
    }

    // 호출자는 먼저 lockAndFindLog로 같은 요청의 잠금을 획득해야 한다.
    public void linkExistingWafDetection(LogEntry entry){
        String requestId = entry.getRequestId();

        if(requestId == null){
            return;
        }

        wafDetectionRepository.findByRequestId(requestId)
                .ifPresent(wafDetection ->
                        wafDetection.getDetectedThreat()
                                .linkLogEntry(entry)
                        );

    }

    private void validateRequestId(String requestId){
        if(requestId == null
        || requestId.isBlank()
        || requestId.length() > 255){
            throw new IllegalArgumentException(
                    "Request ID must contain 1 to 255 characters."
            );
        }
    }
}

/*
    LogService 또는 WafDetectionWriter 트랜잭션 시작
        → 같은 요청 ID 잠금
        → 조회·저장·연결
        → 커밋 또는 롤백
        → 잠금 해제
* */
