package com.example.security_log_system.dto;

import com.example.security_log_system.dto.WafDetectionEventDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class WafDetectionEventDtoTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // 실제 운영 로그가 아닌 DTO 검증용 예시
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
              "anomaly_score": 5,
              "matched_rules": [
                {
                  "id": "941100",
                  "message": "Test rule matched",
                  "severity": "2",
                  "matched_variable": "ARGS:q",
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

    @Test
    @DisplayName("정상 WAF 이벤트의 JSON 필드를 DTO로 변환하고 검증을 통과한다")
    void validEvent_mapsJsonFieldsAndPassesValidation() throws Exception {
        WafDetectionEventDto event = objectMapper.readValue(
                VALID_JSON,
                WafDetectionEventDto.class
        );

        assertThat(validator.validate(event)).isEmpty();
        assertThat(event.getRequestId()).isEqualTo("test-request-001");
        assertThat(event.getAnomalyScore()).isEqualTo(5);
        assertThat(event.getMatchedRules()).hasSize(1);
        assertThat(event.getMatchedRules().get(0).getAttackTypes())
                .containsExactly("attack-xss");
    }

    @Test
    @DisplayName("선택 필드가 없어도 검증을 통과하고 누락된 숫자는 null, 공격 태그는 빈 목록으로 유지한다")
    void missingOptionalFields_areAccepted() throws Exception {
        ObjectNode json = validJson();
        json.remove("status");
        json.remove("anomaly_score");

        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.remove("message");
        rule.remove("severity");
        rule.remove("matched_variable");
        rule.remove("attack_types");

        WafDetectionEventDto event = toDto(json);

        assertThat(validator.validate(event)).isEmpty();
        assertThat(event.getStatus()).isNull();
        assertThat(event.getAnomalyScore()).isNull();
        assertThat(event.getMatchedRules().get(0).getAttackTypes())
                .isEmpty();
    }

    @Test
    @DisplayName("요청 ID가 없으면 requestId 필드 검증에 실패한다")
    void missingRequestId_failsValidation() throws Exception {
        ObjectNode json = validJson();
        json.remove("request_id");

        assertThat(validator.validate(toDto(json)))
                .anyMatch(violation ->
                        violation.getPropertyPath().toString()
                                .equals("requestId"));
    }

    @Test
    @DisplayName("매칭된 규칙 목록이 비어 있으면 검증에 실패한다")
    void emptyRules_failsValidation() throws Exception {
        ObjectNode json = validJson();
        json.putArray("matched_rules");

        assertThat(validator.validate(toDto(json)))
                .anyMatch(violation ->
                        violation.getPropertyPath().toString()
                                .equals("matchedRules"));
    }

    @Test
    @DisplayName("목록 안의 규칙 ID가 없으면 중첩 DTO 검증에 실패한다")
    void missingRuleId_failsNestedValidation() throws Exception {
        ObjectNode json = validJson();
        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.remove("id");

        assertThat(validator.validate(toDto(json)))
                .anyMatch(violation ->
                        violation.getPropertyPath().toString()
                                .equals("matchedRules[0].id"));
    }

    @Test
    @DisplayName("탐지 출처와 IP 주소가 잘못되면 두 필드 모두 검증에 실패한다")
    void invalidSourceAndIp_failValidation() throws Exception {
        ObjectNode json = validJson();
        json.put("source", "ai");
        json.put("client_ip", "999.999.999.999");

        assertThat(validator.validate(toDto(json)))
                .anyMatch(violation ->
                        violation.getPropertyPath().toString()
                                .equals("source"))
                .anyMatch(violation ->
                        violation.getPropertyPath().toString()
                                .equals("clientIp"));
    }

    @Test
    @DisplayName("공격 태그가 빈 JSON 객체이면 빈 목록으로 변환하고 검증을 통과한다")
    void emptyObjectAttackTypes_isAcceptedAsEmptyList() throws Exception {
        ObjectNode json = validJson();
        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.putObject("attack_types");

        WafDetectionEventDto event = toDto(json);

        assertThat(validator.validate(event)).isEmpty();
        assertThat(event.getMatchedRules().get(0).getAttackTypes())
                .isEmpty();
    }

    @Test
    @DisplayName("공격 태그가 배열 대신 문자열이면 JSON 변환에 실패한다")
    void invalidAttackTypesShape_failsJsonMapping() throws Exception {
        ObjectNode json = validJson();
        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.put("attack_types", "attack-xss");

        assertThatThrownBy(() -> toDto(json))
                .isInstanceOf(
                        com.fasterxml.jackson.core.JsonProcessingException.class
                );
    }


    private ObjectNode validJson() throws Exception{
        return (ObjectNode) objectMapper.readTree(VALID_JSON);
    }

    private WafDetectionEventDto toDto(ObjectNode json) throws Exception{
        return objectMapper.treeToValue(json, WafDetectionEventDto.class);
    }


}
