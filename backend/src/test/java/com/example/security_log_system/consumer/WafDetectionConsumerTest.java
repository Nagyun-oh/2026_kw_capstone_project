package com.example.security_log_system.consumer;


import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.exception.InvalidWafEventException;
import com.example.security_log_system.kafka.WafDetectionConsumer;
import com.example.security_log_system.service.WafDetectionHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class WafDetectionConsumerTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private WafDetectionHandler wafDetectionHandler;

    private WafDetectionConsumer consumer;

    private static final String VALID_JSON = """
            {
                          "source": "waf",
                          "event_type": "waf_detection",
                          "request_id": "test-request-001",
                          "time": "Sat Oct 10 05:00:00 2026",
                          "client_ip": "203.0.113.10",
                          "method": "GET",
                          "path": "/test",
                          "status": 200,
                          "matched_rules": [
                            {
                              "id": "941100",
                              "message": "Test rule matched",
                              "severity": "2",
                              "attack_types": ["attack-xss"]
                            }
                          ]
                        }
            """;

    @BeforeAll
    static void setUpValidator(){
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidator(){
        validatorFactory.close();
    }

    @BeforeEach
    void setUp(){
        consumer = new WafDetectionConsumer(
                objectMapper,
                validator,
                wafDetectionHandler
        );
    }

    @Test
    @DisplayName("정상 WAF 이벤트를 변환·검증한 뒤 저장 담당 코드에 전달한다")
    void validEvent_isPassedToHandler(){
        consumer.consume(record(VALID_JSON));

        ArgumentCaptor<WafDetectionEventDto> captor =
                ArgumentCaptor.forClass(WafDetectionEventDto.class);

        verify(wafDetectionHandler).handle(captor.capture());

        WafDetectionEventDto event = captor.getValue();

        assertThat(event.getRequestId()).isEqualTo("test-request-001");
        assertThat(event.getClientIp()).isEqualTo("203.0.113.10");
        assertThat(event.getMatchedRules()).hasSize(1);

        // 선택 필드가 없어도 정상적으로 전달한다.
        assertThat(event.getAnomalyScore()).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings ={
            " ",
            "null",
            "not-json",
            "[]"
    })
    @DisplayName("빈 메시지나 잘못된 JSON 구조는 거부하고 저장 담당 코드를 호출하지 않는다")
    void invalidMessage_isRejected(String message){
        assertThatThrownBy(() -> consumer.consume(record(message)))
                .isInstanceOf(InvalidWafEventException.class);
        verifyNoInteractions(wafDetectionHandler);
    }

    @Test
    @DisplayName("정상 JSON 뒤에 다른 JSON이 붙으면 거부한다")
    void trailingJson_isRejected(){
        String message = VALID_JSON + "{}";

        assertThatThrownBy(()-> consumer.consume(record(message)))
                .isInstanceOf(InvalidWafEventException.class);
        verifyNoInteractions(wafDetectionHandler);
    }

    @Test
    @DisplayName("요청 ID가 없으면 검증에 실패하고 저장 담당 코드를 호출하지 않는다")
    void missingRequestId_isRejected() throws Exception{
        ObjectNode json = (ObjectNode) objectMapper.readTree(VALID_JSON);
        json.remove("request_id");

        assertThatThrownBy(
                () -> consumer.consume(record(json.toString()))
        )
                .isInstanceOf(InvalidWafEventException.class)
                .hasMessageContaining("requestId");

        verifyNoInteractions(wafDetectionHandler);
    }

    @Test
    @DisplayName("중첩 규칙의 ID가 없으면 검증에 실패한다")
    void missingRuleId_isRejected() throws Exception{
        ObjectNode json = (ObjectNode) objectMapper.readTree(VALID_JSON);
        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.remove("id");

        assertThatThrownBy(
                () -> consumer.consume(record(json.toString()))
        )
                .isInstanceOf(InvalidWafEventException.class)
                .hasMessageContaining("matchedRules[0].id");
        verifyNoInteractions(wafDetectionHandler);
    }

    @Test
    @DisplayName("저장 처리 오류를 삼키지 않고 Kafka 오류 처리기로 전달하도록 예외를 전파한다")
    void handlerFailure_isPropagated(){
        RuntimeException databaseFailure = new RuntimeException("Database failure");

        doThrow(databaseFailure)
                .when(wafDetectionHandler)
                .handle(any(WafDetectionEventDto.class));

        assertThatThrownBy(
                () -> consumer.consume(record(VALID_JSON))
        ).isSameAs(databaseFailure);

    }


    private ConsumerRecord<String,String> record(String message){
        return new ConsumerRecord<>(
                "waf-detection-topic",
                0,
                10L,
                null,
                message
        );
    }


}
