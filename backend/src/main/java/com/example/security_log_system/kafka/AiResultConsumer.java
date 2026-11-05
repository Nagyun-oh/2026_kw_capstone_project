package com.example.security_log_system.kafka;

import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.exception.InvalidAiResultException;
import com.example.security_log_system.service.ThreatService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AiResultConsumer {

    private final ObjectMapper objectMapper;
    private final ThreatService threatService;


    // ai-result-topic에서 AI 분석 결과를 받아 파싱·검증 후 위협 정보로 저장 (예외는 컨테이너 에러 핸들러로 전달)
    @KafkaListener(
            topics = "ai-result-topic",
            groupId = "ai-result-group",
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void consume(String message) {
        AiResponseDto response = parse(message);

        validate(response);

        // 업무 예외는 잡아서 끝내지 않고 컨테이너로 전달한다.
        threatService.saveAiDetectedThreat(response);

        // Service 트랜잭션이 성공한 뒤에만 출력한다.
        log.info(
                "AI analysis result received. logId={}",
                response.getLogId()
        );
    }

    // 메시지가 비어 있지 않은지 확인하고 AiResponseDto로 엄격하게 역직렬화 (뒤에 붙은 토큰도 거부, 원문은 예외에 남기지 않음)
    private AiResponseDto parse(String message) {
        if (message == null || message.isBlank()) {
            throw new InvalidAiResultException(
                    "EMPTY_AI_RESULT"
            );
        }

        try {
            return objectMapper
                    .readerFor(AiResponseDto.class)
                    .with(
                            DeserializationFeature
                                    .FAIL_ON_TRAILING_TOKENS
                    )
                    .readValue(message);

        } catch (JsonProcessingException exception) {
            // 원문 JSON·민감정보가 오류 메시지에 섞이지 않게 한다.
            throw new InvalidAiResultException(
                    "INVALID_AI_RESULT_JSON"
            );
        }
    }

    // 필수 필드 검증: logId는 양수, threatScore는 0~1 사이 유한값, ipAddress는 공백이 아니어야 함
    private void validate(AiResponseDto response) {
        if (response == null
                || response.getLogId() == null
                || response.getLogId() <= 0) {
            throw new InvalidAiResultException(
                    "INVALID_AI_RESULT_LOG_ID"
            );
        }

        Float score = response.getThreatScore();

        if (score == null
                || !Float.isFinite(score)
                || score < 0.0f
                || score > 1.0f) {
            throw new InvalidAiResultException(
                    "INVALID_AI_RESULT_SCORE"
            );
        }

        if (response.getIpAddress() == null
                || response.getIpAddress().isBlank()) {
            throw new InvalidAiResultException(
                    "INVALID_AI_RESULT_IP"
            );
        }
    }
}