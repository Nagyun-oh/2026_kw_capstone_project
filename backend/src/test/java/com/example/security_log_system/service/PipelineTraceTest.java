package com.example.security_log_system.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class PipelineTraceTest {

    private final ObjectMapper mapper = spy(new ObjectMapper());

    @AfterEach
    void cleanup() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
        TransactionSynchronizationManager.setActualTransactionActive(false);
    }

    private void beginTransaction() {
        TransactionSynchronizationManager.initSynchronization();
        TransactionSynchronizationManager.setActualTransactionActive(true);
    }

    @Test
    @DisplayName("등록 시점에는 기록하지 않고 커밋 후 콜백에서 UTC 시각을 기록한다")
    void recordsOnlyAfterCommit() throws Exception {
        beginTransaction();
        PipelineTrace trace = new PipelineTrace(true, mapper);

        trace.afterCommit(
                "LOG_COMMITTED", "CREATED", "Request-A", 10L, null
        );

        verify(mapper, never()).writeValueAsString(any());

        var callbacks =
                TransactionSynchronizationManager.getSynchronizations();

        assertThat(callbacks).hasSize(1);
        callbacks.get(0).afterCommit();

        ArgumentCaptor<PipelineTrace.Point> captor =
                ArgumentCaptor.forClass(PipelineTrace.Point.class);

        verify(mapper).writeValueAsString(captor.capture());

        PipelineTrace.Point point = captor.getValue();
        assertThat(point.stage()).isEqualTo("LOG_COMMITTED");
        assertThat(point.requestId()).isEqualTo("Request-A");
        assertThat(point.logId()).isEqualTo(10L);
        assertThatCode(() -> Instant.parse(point.at()))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("롤백 시 커밋 성공 기록을 남기지 않는다")
    void rollbackDoesNotRecordSuccess() throws Exception {
        beginTransaction();
        PipelineTrace trace = new PipelineTrace(true, mapper);

        trace.afterCommit(
                "WAF_COMMITTED", "CREATED", "Request-A", null, 20L
        );

        for (var callback :
                TransactionSynchronizationManager.getSynchronizations()) {
            callback.afterCompletion(
                    TransactionSynchronization.STATUS_ROLLED_BACK
            );
        }

        verify(mapper, never()).writeValueAsString(any());
    }

    @Test
    @DisplayName("계측이 꺼져 있으면 커밋 콜백과 전송 기록을 만들지 않는다")
    void disabledTraceDoesNothing() throws Exception {
        beginTransaction();
        PipelineTrace trace = new PipelineTrace(false, mapper);

        trace.afterCommit(
                "LOG_COMMITTED", "CREATED", "Request-A", 10L, null
        );
        trace.alertSend(
                "ALERT_SEND_BEGIN", "request:Request-A",
                "alert-1", 1L, List.of("WAF")
        );

        assertThat(
                TransactionSynchronizationManager.getSynchronizations()
        ).isEmpty();

        verify(mapper, never()).writeValueAsString(any());
    }

    @Test
    @DisplayName("트랜잭션이 없으면 즉시 커밋 성공으로 기록하지 않는다")
    void noTransactionDoesNotInventCommit() throws Exception {
        PipelineTrace trace = new PipelineTrace(true, mapper);

        trace.afterCommit(
                "LOG_COMMITTED", "CREATED", "Request-A", 10L, null
        );

        verify(mapper, never()).writeValueAsString(any());
    }

    @Test
    @DisplayName("측정 로그 직렬화 실패를 업무 처리 예외로 전파하지 않는다")
    void serializationFailureDoesNotPropagate() throws Exception {
        PipelineTrace trace = new PipelineTrace(true, mapper);

        doThrow(new IllegalStateException("test"))
                .when(mapper).writeValueAsString(any());

        assertThatCode(() -> trace.alertSend(
                "ALERT_SEND_RETURNED", "request:Request-A",
                "alert-1", 2L, List.of("WAF", "AI")
        )).doesNotThrowAnyException();
    }
}