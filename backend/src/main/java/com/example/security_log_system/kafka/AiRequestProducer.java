package com.example.security_log_system.kafka;

import com.example.security_log_system.dto.AiRequestDto;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

// TODO: DLQ 처리 고민

@Slf4j
@Component
@RequiredArgsConstructor
public class AiRequestProducer {

    private static final String AI_REQUEST_TOPIC = "ai-request-topic";

    private final KafkaTemplate<String,String> kafkaTemplate;   // Kafka 전송 역할
    private final ObjectMapper objectMapper;                    // AiRequestDto를 JSON 문자열로 변환하는 역할
    private final MeterRegistry meterRegistry;

    public void sendAnalysisRequest(AiRequestDto request){
        Timer.Sample sample = Timer.start(meterRegistry);
        String result = "success";

        try {
            String message = objectMapper.writeValueAsString(request);
            kafkaTemplate.send(
                    AI_REQUEST_TOPIC,
                    String.valueOf(request.getLogId()),
                    message);

            Counter.builder("security.ai.request.produced")
                            .description("Number of AI analysis request messages produced to Kafka")
                            .register(meterRegistry)
                            .increment();

            log.info("AI analysis request sent. logId={}",request.getLogId());
        } catch (JsonProcessingException e){
            result = "failure";

            Counter.builder("security.ai.request.produce.failures")
                    .description("Number of AI analysis request message produce failures")
                    .register(meterRegistry)
                    .increment();

            throw new RuntimeException("AI analysis request serialization failed.",e);
        } finally {
            sample.stop(
                    Timer.builder("security.ai.request.produce.duration")
                            .description("Time taken to produce one AI analysis request message")
                            .tag("result",result)
                            .register(meterRegistry)
            );
        }

    }
}