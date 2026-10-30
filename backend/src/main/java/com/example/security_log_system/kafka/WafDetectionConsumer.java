package com.example.security_log_system.kafka;


import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.exception.InvalidWafEventException;
import com.example.security_log_system.service.WafDetectionHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.kafka.waf",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = false
)
public class WafDetectionConsumer {

    private final ObjectMapper objectMapper;
    private final Validator validator;
    private final WafDetectionHandler wafDetectionHandler;

    @KafkaListener(
            topics = "waf-detection-topic",
            groupId = "waf-detection-group",
            containerFactory = "wafKafkaListenerContainerFactory"
    )
    public void consume(ConsumerRecord<String,String>record){

        WafDetectionEventDto event = parseAndValidate(record.value());

        // 저장 실패 예외를 잡고 정상 종료하지 않는다.
        // 예외가 Kafka 오류 처리기로 전달돼야 재시도 할 수 있다.
        wafDetectionHandler.handle(event);

        log.debug(
                "WAF event handled. topic = {}, partition={}, offset={}",
                record.topic(),
                record.partition(),
                record.offset()
        );
    }

    private WafDetectionEventDto parseAndValidate(String message){

        if(message == null || message.isBlank()){
            throw new InvalidWafEventException("WAF event message is empty.");
        }

        WafDetectionEventDto event;

        try{
            event = objectMapper
                    .readerFor(WafDetectionEventDto.class)
                    .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS) // 정상 JSON 뒤에 다른 JSON이 붙어 있는 경우 거부
                    .readValue(message);
        } catch( JsonProcessingException exception){
            // 파싱 예외에 포함될 수 있는 원문 데이터는 메시지에 붙이지 않는다.
            throw new InvalidWafEventException("WAF event JSON cannot be parsed.");
        }

        // JSON 문자열 "null"은 변환 결과가 null이므로 별도로 검사한다.
        if(event == null){
            throw new InvalidWafEventException("WAF event must not be null.");
        }


        // DTO의 검증 규칙을 실행하고, 잘못된 필드가 있으면 그 이름을 모아서 예외를 던진다.
        Set<ConstraintViolation<WafDetectionEventDto>> violations = validator.validate(event);

        // 검증 실패가 있는지 확인
        if(!violations.isEmpty()){
            // 잘못된 필드 이름을 문자열로 만들기
            String invalidFields = violations.stream()
                    .map(violation ->
                            violation.getPropertyPath().toString())
                    .distinct()
                    .sorted()
                    .collect(Collectors.joining(", "));
            // 예외를 던져 저장 진행 중단
            throw new InvalidWafEventException("WAF event validation failed. fields="+invalidFields);
        }

        return event;
    }
}
