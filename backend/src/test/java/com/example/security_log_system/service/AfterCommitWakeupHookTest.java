package com.example.security_log_system.service;

import com.example.security_log_system.dto.AiRequestDto;
import com.example.security_log_system.repository.AiRequestOutboxRepository;
import com.example.security_log_system.repository.RequestAlertRepository;
import com.example.security_log_system.repository.RequestAlertRepository.AlertState;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/** 발행 대기 행을 만드는 두 지점이 저장 뒤에 커밋 후 깨우기를 요청하는지 확인한다. */
class AfterCommitWakeupHookTest {

    @Test
    @DisplayName("AI outbox 행을 저장한 뒤 커밋 후 깨우기를 요청한다")
    void outboxEnqueueRequestsWakeupAfterInsert() {
        AiRequestOutboxRepository repository = mock(AiRequestOutboxRepository.class);
        AiRequestOutboxWakeup wakeup = mock(AiRequestOutboxWakeup.class);
        AiRequestOutboxService service = new AiRequestOutboxService(repository, new ObjectMapper(), wakeup);

        service.enqueue(AiRequestDto.builder().logId(7L).method("GET").urlPath("/").build());

        InOrder order = inOrder(repository, wakeup);
        order.verify(repository).insert(eq(7L), anyString());
        order.verify(wakeup).requestAfterCommit();
    }

    @Test
    @DisplayName("저장하지 못한 요청은 깨우기를 요청하지 않는다")
    void invalidOutboxRequestDoesNotWake() {
        AiRequestOutboxWakeup wakeup = mock(AiRequestOutboxWakeup.class);
        AiRequestOutboxService service =
                new AiRequestOutboxService(mock(AiRequestOutboxRepository.class), new ObjectMapper(), wakeup);

        assertThatThrownBy(() -> service.enqueue(AiRequestDto.builder().logId(0L).build()))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(wakeup);
    }

    private static AlertState state(boolean waf, boolean ai, int level) {
        return new AlertState("request:r1", "alert-1", "192.0.2.1", waf, ai, level, 1, 1, false, LocalDateTime.now());
    }

    @Test
    @DisplayName("알림이 새 revision으로 발행 대기가 되면 커밋 후 깨우기를 요청한다")
    void changedAlertRequestsWakeup() {
        RequestAlertRepository repository = mock(RequestAlertRepository.class);
        RequestAlertWakeup wakeup = mock(RequestAlertWakeup.class);
        when(repository.findForUpdate("request:r1")).thenReturn(Optional.of(state(true, false, 3)));

        new RequestAlertService(repository, wakeup).recordAi("r1", 10L, "192.0.2.1", "HIGH");

        InOrder order = inOrder(repository, wakeup);
        order.verify(repository).updateDetection("request:r1", true, true, 3);
        order.verify(wakeup).requestAfterCommit();
    }

    @Test
    @DisplayName("탐지 내용이 바뀌지 않으면 발행할 것이 없으므로 깨우지 않는다")
    void unchangedAlertDoesNotWake() {
        RequestAlertRepository repository = mock(RequestAlertRepository.class);
        RequestAlertWakeup wakeup = mock(RequestAlertWakeup.class);
        when(repository.findForUpdate("request:r1")).thenReturn(Optional.of(state(true, false, 3)));

        new RequestAlertService(repository, wakeup).recordWaf("r1", "192.0.2.1", "HIGH");

        verify(repository, never()).updateDetection(anyString(), anyBoolean(), anyBoolean(), anyInt());
        verifyNoInteractions(wakeup);
    }
}
