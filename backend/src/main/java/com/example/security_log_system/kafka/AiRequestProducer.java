package com.example.security_log_system.kafka;

import com.example.security_log_system.config.AiRequestTopicConfig;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

@Slf4j
@Component
@RequiredArgsConstructor
public class AiRequestProducer {

    // 토픽 이름·파티션 수는 AiRequestTopicConfig 한 곳에서 관리한다.
    private static final String AI_REQUEST_TOPIC =
            AiRequestTopicConfig.AI_REQUEST_TOPIC;

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final MeterRegistry meterRegistry;

    // 아웃박스에 저장된 AI 요청을 logId를 키로 ai-request-topic에 비동기 전송하고, 전송 결과(성공/실패)를 메트릭·로그로 기록
    public CompletableFuture<SendResult<String, String>> sendStored(
            long logId,
            String payload
    ) {
        Timer.Sample sample = Timer.start(meterRegistry);

        try {
            CompletableFuture<SendResult<String, String>> future =
                    kafkaTemplate.send(
                            AI_REQUEST_TOPIC,
                            String.valueOf(logId),
                            payload
                    );

            future.whenComplete((result, exception) ->
                    recordOutcome(logId, sample, exception)
            );

            return future;
        } catch (RuntimeException exception) {
            recordOutcome(logId, sample, exception);
            throw exception;
        }
    }

    // 전송 결과에 따라 성공/실패 카운터 증가, 전송 소요 시간 기록, 결과 로그 출력
    private void recordOutcome(
            long logId,
            Timer.Sample sample,
            Throwable exception
    ) {
        boolean success = exception == null;

        Counter.builder(success
                        ? "security.ai.request.produced"
                        : "security.ai.request.produce.failures")
                .register(meterRegistry)
                .increment();

        sample.stop(
                Timer.builder("security.ai.request.produce.duration")
                        .tag("result", success ? "success" : "failure")
                        .register(meterRegistry)
        );

        if (success) {
            log.info(
                    "AI request acknowledged by Kafka. logId={}",
                    logId
            );
        } else {
            log.warn(
                    "AI request Kafka send failed. logId={}, code={}",
                    logId,
                    exception.getClass().getSimpleName()
            );
        }
    }
}