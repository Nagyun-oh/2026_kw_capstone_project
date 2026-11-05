package com.example.security_log_system.config;

import com.example.security_log_system.exception.InvalidAiResultException;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.common.TopicPartition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.util.backoff.FixedBackOff;

@Slf4j
@Configuration
public class PipelineKafkaErrorConfig {

    public static final String AI_RESULT_DLT =
            "ai-result-topic.DLT";

    public static final String LOG_DLT =
            "log-topic.DLT";

    @Bean
    public NewTopic aiResultDltTopic() {
        return TopicBuilder.name(AI_RESULT_DLT)
                .partitions(1)
                .replicas(1)
                .config("cleanup.policy", "delete")
                .config("retention.ms", "604800000")
                .build();
    }

    @Bean
    public NewTopic logDltTopic() {
        return TopicBuilder.name(LOG_DLT)
                .partitions(1)
                .replicas(1)
                .config("cleanup.policy", "delete")
                .config("retention.ms", "604800000")
                .build();
    }

    @Bean
    public DeadLetterPublishingRecoverer pipelineDltRecoverer(
            KafkaTemplate<String, String> kafkaTemplate
    ) {
        DeadLetterPublishingRecoverer recoverer =
                new DeadLetterPublishingRecoverer(
                        kafkaTemplate,
                        (record, exception) -> {
                            String target = switch (record.topic()) {
                                case "ai-result-topic" ->
                                        AI_RESULT_DLT;
                                case "log-topic" ->
                                        LOG_DLT;
                                default ->
                                        throw new IllegalArgumentException(
                                                "Unsupported pipeline topic"
                                        );
                            };

                            return new TopicPartition(target, -1);
                        }
                );

        // DLT 전송에 실패하면 복구 성공으로 처리하지 않는다.
        recoverer.setFailIfSendResultIsError(true);

        return recoverer;
    }

    @Bean
    public DefaultErrorHandler pipelineErrorHandler(
            DeadLetterPublishingRecoverer pipelineDltRecoverer
    ) {
        DefaultErrorHandler handler =
                new DefaultErrorHandler(
                        pipelineDltRecoverer,
                        new FixedBackOff(1000L, 2L)
                );

        // 입력 자체가 잘못된 경우 재시도하지 않는다.
        handler.addNotRetryableExceptions(
                InvalidAiResultException.class,
                JsonProcessingException.class
        );

        handler.setAckAfterHandle(true);

        // 원문 메시지 대신 위치·횟수·오류 종류만 기록한다.
        handler.setRetryListeners(
                (record, exception, deliveryAttempt) ->
                        log.warn(
                                "Kafka processing failed. "
                                        + "topic={}, partition={}, "
                                        + "offset={}, attempt={}, code={}",
                                record.topic(),
                                record.partition(),
                                record.offset(),
                                deliveryAttempt,
                                exception.getClass().getSimpleName()
                        )
        );

        return handler;
    }
}