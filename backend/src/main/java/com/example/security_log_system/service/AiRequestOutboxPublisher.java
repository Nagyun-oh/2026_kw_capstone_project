package com.example.security_log_system.service;

import com.example.security_log_system.kafka.AiRequestProducer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

// 실제 발행기
@Slf4j
@Service
@RequiredArgsConstructor
public class AiRequestOutboxPublisher {

    private final AiRequestOutboxService outboxService;
    private final AiRequestProducer producer;

    // Kafka를 기다리는 동안 DB 트랜잭션을 유지하지 않는다.
    public boolean publishNext() {
        AiRequestOutboxService.Job job =
                outboxService.claimNext().orElse(null);

        if (job == null) {
            return false;
        }

        try {
            producer.sendStored(
                    job.logId(),
                    job.payload()
            ).get(20, TimeUnit.SECONDS);

        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            // 선점 만료 후 다른 실행에서 복구한다.
            log.warn(
                    "AI outbox publisher interrupted. logId={}",
                    job.logId()
            );

            return false;

        } catch (Exception exception) {
            Throwable cause = exception.getCause() == null
                    ? exception
                    : exception.getCause();

            String code = cause.getClass().getSimpleName();

            outboxService.retry(job, code);

            log.warn(
                    "AI outbox retry scheduled. logId={}, code={}",
                    job.logId(),
                    code
            );

            return false;
        }

        // Kafka 성공 이후에만 실행한다.
        // 이 DB 처리 자체가 실패하면 IN_FLIGHT가 남아
        // 선점 만료 후 재발행될 수 있다.
        outboxService.markSent(job);

        return true;
    }
}