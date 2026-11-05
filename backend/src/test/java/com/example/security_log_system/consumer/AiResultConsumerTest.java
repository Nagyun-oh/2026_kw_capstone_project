package com.example.security_log_system.consumer;

import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.exception.AiLogNotReadyException;
import com.example.security_log_system.exception.InvalidAiResultException;
import com.example.security_log_system.kafka.AiResultConsumer;
import com.example.security_log_system.service.ThreatService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AiResultConsumerTest {

    private static final String VALID_JSON = """
            {
              "log_id": 1,
              "threat_score": 0.9,
              "ip_address": "192.0.2.10",
              "reason": "test detection"
            }
            """;

    @Mock
    private ThreatService threatService;

    private AiResultConsumer consumer;

    @BeforeEach
    void setUp() {
        consumer = new AiResultConsumer(
                new ObjectMapper(),
                threatService
        );
    }

    @Test
    @DisplayName("정상 AI 결과를 파싱하여 서비스에 전달한다")
    void validResult_isPassedToService() {
        consumer.consume(VALID_JSON);

        ArgumentCaptor<AiResponseDto> captor =
                ArgumentCaptor.forClass(AiResponseDto.class);

        verify(threatService)
                .saveAiDetectedThreat(captor.capture());

        assertThat(captor.getValue().getLogId())
                .isEqualTo(1L);

        assertThat(captor.getValue().getThreatScore())
                .isEqualTo(0.9f);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "invalid-json",
            "null",
            "{\"log_id\":1,\"ip_address\":\"0.0.0.0\"}",
            "{\"log_id\":0,\"threat_score\":0.1,\"ip_address\":\"0.0.0.0\"}",
            "{\"log_id\":1,\"threat_score\":2.0,\"ip_address\":\"0.0.0.0\"}",
            "{\"log_id\":1,\"threat_score\":0.1}"
    })
    @DisplayName("잘못된 AI 결과는 입력 오류를 전파하고 서비스를 호출하지 않는다")
    void invalidResult_isRejected(String message) {
        assertThatThrownBy(() -> consumer.consume(message))
                .isInstanceOf(InvalidAiResultException.class);

        verifyNoInteractions(threatService);
    }

    @Test
    @DisplayName("정상 JSON 뒤에 다른 JSON이 붙어 있으면 거부한다")
    void trailingJson_isRejected() {
        assertThatThrownBy(() ->
                consumer.consume(VALID_JSON + "{}")
        ).isInstanceOf(InvalidAiResultException.class);

        verifyNoInteractions(threatService);
    }

    @Test
    @DisplayName("서비스 저장 실패를 삼키지 않고 컨테이너에 전달한다")
    void serviceFailure_isPropagated() {
        RuntimeException failure =
                new RuntimeException("test database failure");

        doThrow(failure)
                .when(threatService)
                .saveAiDetectedThreat(any());

        assertThatThrownBy(() ->
                consumer.consume(VALID_JSON)
        ).isSameAs(failure);
    }

    @Test
    @DisplayName("원본 로그 미확인 예외를 재시도할 수 있도록 전파한다")
    void missingLog_isPropagated() {
        AiLogNotReadyException failure =
                new AiLogNotReadyException(1L);

        doThrow(failure)
                .when(threatService)
                .saveAiDetectedThreat(any());

        assertThatThrownBy(() ->
                consumer.consume(VALID_JSON)
        ).isSameAs(failure);
    }
}