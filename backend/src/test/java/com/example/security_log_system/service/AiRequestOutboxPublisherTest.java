package com.example.security_log_system.service;

import com.example.security_log_system.kafka.AiRequestProducer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.kafka.support.SendResult;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AiRequestOutboxPublisherTest {

    @Mock
    private AiRequestOutboxService outboxService;

    @Mock
    private AiRequestProducer producer;

    @InjectMocks
    private AiRequestOutboxPublisher publisher;

    private final AiRequestOutboxService.Job job =
            new AiRequestOutboxService.Job(
                    1L,
                    "{\"log_id\":1}",
                    "test-lease-token",
                    1L
            );

    @Test
    @DisplayName("Kafka 전송 성공을 확인한 작업만 발행 완료로 기록한다")
    void acknowledgedRequest_isMarkedSent() {
        when(outboxService.claimNext())
                .thenReturn(Optional.of(job));

        when(producer.sendStored(
                job.logId(),
                job.payload()
        )).thenReturn(
                CompletableFuture
                        .<SendResult<String, String>>completedFuture(null)
        );

        publisher.publishNext();

        var order = inOrder(outboxService, producer);

        order.verify(outboxService).claimNext();
        order.verify(producer)
                .sendStored(job.logId(), job.payload());
        order.verify(outboxService).markSent(job);

        verify(outboxService, never())
                .retry(any(), any());
    }

    @Test
    @DisplayName("Kafka 전송에 실패하면 완료 처리하지 않고 재시도를 예약한다")
    void failedRequest_isScheduledForRetry() {
        when(outboxService.claimNext())
                .thenReturn(Optional.of(job));

        CompletableFuture<SendResult<String, String>> failed =
                new CompletableFuture<>();

        failed.completeExceptionally(
                new IllegalStateException("test failure")
        );

        when(producer.sendStored(
                job.logId(),
                job.payload()
        )).thenReturn(failed);

        publisher.publishNext();

        verify(outboxService)
                .retry(eq(job), eq("IllegalStateException"));

        verify(outboxService, never())
                .markSent(any());
    }
}