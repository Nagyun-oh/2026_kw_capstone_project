package com.example.security_log_system.kafka;

import com.example.security_log_system.service.LogService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

// TODO: DLQ 처리 고민

@Slf4j
@Component
@RequiredArgsConstructor
public class LogKafkaConsumer {

    private final LogService logService;
    private final MeterRegistry meterRegistry;

    @KafkaListener(topics = "log-topic",groupId="log-group",containerFactory = "kafkaListenerContainerFactory")
    public void consume(String message){
        Timer.Sample sample = Timer.start(meterRegistry);
        String result = "success";

        try {
            logService.processRawLog(message);

            Counter.builder("security.logs.processed")
                    .description("Number of successfully processed log messages")
                    .register(meterRegistry)
                    .increment();

        } catch (Exception exception) {
            log.error("Failed to process Kafka log message",exception);

            result = "failure";

            Counter.builder("security.kafka.consumer.failures")
                    .description("Number of Kafka log consumer processing failures")
                    .register(meterRegistry)
                    .increment();
        } finally {
            sample.stop(
                    Timer.builder("security.log.processing.duration")
                            .description("Time taken to process one Kafka log message")
                            .tag("result",result)
                            .register(meterRegistry)
            );
        }
    }
}
