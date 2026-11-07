package com.example.security_log_system.service;

import com.example.security_log_system.config.OutboxSchedulingConfig;
import com.example.security_log_system.kafka.AiRequestProducer;
import com.example.security_log_system.repository.AiRequestOutboxRepository;
import com.example.security_log_system.repository.RequestAlertRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * DB 없이 실제 빈 연결을 확인한다.
 * - outbox 서비스 → 깨우기 → (실행 시점) 발행기 → 발행 처리 → outbox 서비스 순환이 생성 시점에 문제없는지
 * - 깨우기가 각 발행기의 @Scheduled와 같은 단일 스레드 스케줄러에서 실행되는지
 */
@SpringJUnitConfig(classes = {
        OutboxSchedulingConfig.class,
        AfterCommitWakeupWiringTest.Mocks.class,
        AiRequestOutboxService.class,
        AiRequestOutboxPublisher.class,
        AiRequestOutboxDispatcher.class,
        AiRequestOutboxWakeup.class,
        RequestAlertService.class,
        RequestAlertDispatcher.class,
        RequestAlertWakeup.class
})
class AfterCommitWakeupWiringTest {

    @Configuration
    static class Mocks {
        @Bean AiRequestOutboxRepository outboxRepository() { return mock(AiRequestOutboxRepository.class); }
        @Bean AiRequestProducer producer() { return mock(AiRequestProducer.class); }
        @Bean ObjectMapper objectMapper() { return new ObjectMapper(); }
        @Bean RequestAlertRepository alertRepository() { return mock(RequestAlertRepository.class); }
        @Bean RequestAlertPublisher alertPublisher() { return mock(RequestAlertPublisher.class); }
        @Bean SimpMessagingTemplate messagingTemplate() { return mock(SimpMessagingTemplate.class); }
    }

    @Autowired AiRequestOutboxWakeup outboxWakeup;
    @Autowired RequestAlertWakeup alertWakeup;
    @Autowired AiRequestOutboxRepository outboxRepository;
    @Autowired RequestAlertRepository alertRepository;

    @AfterEach
    void clear() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private static void commit() {
        TransactionSynchronizationManager.getSynchronizations().forEach(TransactionSynchronization::afterCommit);
        TransactionSynchronizationManager.clearSynchronization();
    }

    @Test
    @DisplayName("AI outbox 커밋 후 깨우기는 ai-outbox 스케줄러 스레드에서 발행기를 실행한다")
    void outboxWakeupRunsDispatcherOnOutboxScheduler() throws Exception {
        CompletableFuture<String> thread = new CompletableFuture<>();
        when(outboxRepository.findReadyForUpdate()).thenAnswer(invocation -> {
            thread.complete(Thread.currentThread().getName());
            return Optional.empty();
        });

        TransactionSynchronizationManager.initSynchronization();
        outboxWakeup.requestAfterCommit();
        commit();

        assertThat(thread.get(5, TimeUnit.SECONDS)).startsWith("ai-outbox-");
    }

    @Test
    @DisplayName("알림 커밋 후 깨우기는 기본 taskScheduler 스레드에서 알림 발행기를 실행한다")
    void alertWakeupRunsDispatcherOnDefaultScheduler() throws Exception {
        CompletableFuture<String> thread = new CompletableFuture<>();
        when(alertRepository.findPendingKeys()).thenAnswer(invocation -> {
            thread.complete(Thread.currentThread().getName());
            return List.of();
        });

        TransactionSynchronizationManager.initSynchronization();
        alertWakeup.requestAfterCommit();
        commit();

        assertThat(thread.get(5, TimeUnit.SECONDS)).startsWith("app-scheduler-");
    }
}
