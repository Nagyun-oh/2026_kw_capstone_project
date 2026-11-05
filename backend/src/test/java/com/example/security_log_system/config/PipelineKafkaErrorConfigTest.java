package com.example.security_log_system.config;

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.KafkaException;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;
import org.springframework.kafka.support.SendResult;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class PipelineKafkaErrorConfigTest {

    @Test
    @DisplayName("DLT 전송 실패를 복구 성공으로 처리하지 않고 예외를 전파한다")
    @SuppressWarnings("unchecked")
    void dltSendFailure_isPropagated() {
        KafkaTemplate<String, String> template =
                mock(KafkaTemplate.class);

        ProducerFactory<String, String> producerFactory =
                mock(ProducerFactory.class);

        lenient().when(template.getProducerFactory())
                .thenReturn(producerFactory);

        lenient().when(
                producerFactory.getConfigurationProperties()
        ).thenReturn(Map.of(
                ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG,
                15_000
        ));

        CompletableFuture<SendResult<String, String>> failed =
                new CompletableFuture<>();

        failed.completeExceptionally(
                new IllegalStateException("test send failure")
        );

        when(template.send(
                org.mockito.ArgumentMatchers
                        .<ProducerRecord<String, String>>any()
        )).thenReturn(failed);

        var recoverer = new PipelineKafkaErrorConfig()
                .pipelineDltRecoverer(template);

        ConsumerRecord<String, String> record =
                new ConsumerRecord<>(
                        "ai-result-topic",
                        0,
                        10L,
                        "1",
                        "{\"log_id\":1}"
                );

        assertThatThrownBy(() ->
                recoverer.accept(
                        record,
                        new RuntimeException("test processing failure")
                )
        ).isInstanceOf(KafkaException.class);
    }
}