package com.example.security_log_system.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.List;

@Slf4j
@Component
public class PipelineTrace {

    private final boolean enabled;
    private final ObjectMapper objectMapper;

    public PipelineTrace(
            @Value("${app.testing.trace-enabled:false}") boolean enabled,
            ObjectMapper objectMapper
    ) {
        this.enabled = enabled;
        this.objectMapper = objectMapper;
    }

    public record Point(
            String schema,
            String stage,
            String outcome,
            String requestId,
            Long logId,
            Long threatId,
            String alertId,
            Long revision,
            List<String> sources,
            String at
    ) {
    }

    public void afterCommit(
            String stage,
            String outcome,
            String requestId,
            Long logId,
            Long threatId
    ) {
        if (!enabled) {
            return;
        }

        if (!TransactionSynchronizationManager.isActualTransactionActive()
                || !TransactionSynchronizationManager.isSynchronizationActive()) {
            // 트랜잭션이 없다고 즉시 성공 기록을 남기면 안 된다.
            log.warn("DG_TRACE_UNAVAILABLE stage={} reason=NO_TRANSACTION", stage);
            return;
        }

        // 엔티티 대신 ID 값만 캡처한다.
        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        emit(new Point(
                                "dualguard-trace-v1",
                                stage,
                                outcome,
                                requestId,
                                logId,
                                threatId,
                                null,
                                null,
                                List.of(),
                                Instant.now().toString()
                        ));
                    }
                }
        );
    }

    public void alertSend(
            String stage,
            String alertKey,
            String alertId,
            long revision,
            List<String> sources
    ) {
        if (!enabled) {
            return;
        }

        String requestId =
                alertKey != null && alertKey.startsWith("request:")
                        ? alertKey.substring("request:".length())
                        : null;

        emit(new Point(
                "dualguard-trace-v1",
                stage,
                null,
                requestId,
                null,
                null,
                alertId,
                revision,
                List.copyOf(sources),
                Instant.now().toString()
        ));
    }

    private void emit(Point point) {
        try {
            log.info("DG_TRACE {}", objectMapper.writeValueAsString(point));
        } catch (Exception exception) {
            log.warn(
                    "DG_TRACE_WRITE_FAILED stage={} errorType={}",
                    point.stage(),
                    exception.getClass().getSimpleName()
            );
        }
    }
}

/*
*  공통 측정 기록 클래스:
*       설정이 꺼져 있으면 기록하지 않는다.
*       저장 성공 기록은 트랜잭션 커밋 후에만 남긴다.
*       IP·요청 본문·토큰은 기록하지 않는다.
*       측정 로그 출력 실패가 업무 처리 예외로 전파되지 않도록 한다.
* */