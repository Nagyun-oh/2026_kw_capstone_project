package com.example.security_log_system.service;

import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.WafDetectionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WafDetectionWriterTest {

    private static final String VALID_JSON = """
            {
              "source": "waf",
              "event_type": "waf_detection",
              "request_id": "waf-test-001",
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

    @Mock
    private ThreatRepository threatRepository;

    @Mock
    private WafDetectionRepository wafRepository;

    @Mock
    private RequestCorrelationService requestCorrelationService;

    @Mock
    private RequestAlertService requestAlertService;

    @Mock
    private AutoBlacklistPolicyService autoBlacklistPolicyService;

    private ObjectMapper objectMapper;
    private WafDetectionWriter writer;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();

        writer = new WafDetectionWriter(
                threatRepository,
                wafRepository,
                objectMapper,
                requestCorrelationService,
                requestAlertService,
                autoBlacklistPolicyService,
                "UTC"
        );

        when(threatRepository.save(any(DetectedThreat.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    @DisplayName("원본 로그 없이 WAF 위협과 요청 정보·규칙 근거를 저장한다")
    void eventWithoutAccessLog_isSaved() throws Exception {
        WafDetectionEventDto event =
                objectMapper.readValue(VALID_JSON, WafDetectionEventDto.class);

        writer.saveNewDetection(event);

        WafDetection saved = captureSavedDetection();
        DetectedThreat threat = saved.getDetectedThreat();

        assertThat(threat.getLogEntry()).isNull();
        assertThat(threat.getThreatType()).isEqualTo("WAF Detection");
        assertThat(threat.getSeverity()).isEqualTo("CRITICAL");

        assertThat(saved.getRequestId()).isEqualTo("waf-test-001");
        assertThat(saved.getClientIp()).isEqualTo("203.0.113.10");
        assertThat(saved.getRequestMethod()).isEqualTo("GET");
        assertThat(saved.getRequestPath()).isEqualTo("/test");
        assertThat(saved.getResponseStatus()).isEqualTo(200);
        assertThat(saved.getAnomalyScore()).isNull();

        assertThat(saved.getOccurredAt())
                .isEqualTo(LocalDateTime.of(2026, 10, 10, 5, 0));

        assertThat(saved.getReceivedAt()).isNotNull();
        assertThat(threat.getDetectedAt()).isEqualTo(saved.getReceivedAt());

        assertThat(
                objectMapper.readTree(saved.getMatchedRulesJson())
                        .get(0).get("id").asText()
        ).isEqualTo("941100");

        verify(requestAlertService).recordWaf(
                "waf-test-001",
                "203.0.113.10",
                "CRITICAL"
        );
    }

    @Test
    @DisplayName("발생 시각을 해석하지 못해도 원문과 탐지 정보는 보존한다")
    void invalidTime_isPreservedWithoutInventingTimestamp() throws Exception {
        ObjectNode json = (ObjectNode) objectMapper.readTree(VALID_JSON);
        json.put("time", "unsupported-time");

        writer.saveNewDetection(
                objectMapper.treeToValue(json, WafDetectionEventDto.class)
        );

        WafDetection saved = captureSavedDetection();

        assertThat(saved.getOccurredAt()).isNull();
        assertThat(saved.getEventTimeRaw()).isEqualTo("unsupported-time");
        assertThat(saved.getReceivedAt()).isNotNull();
    }

    @Test
    @DisplayName("WAF 생성 시간대가 한국이면 UTC로 변환해 저장한다")
    void koreanEventTime_isConvertedToUtc() throws Exception {
        writer = new WafDetectionWriter(
                threatRepository,
                wafRepository,
                objectMapper,
                requestCorrelationService,
                requestAlertService,
                autoBlacklistPolicyService,
                "Asia/Seoul"
        );

        writer.saveNewDetection(
                objectMapper.readValue(VALID_JSON, WafDetectionEventDto.class)
        );

        assertThat(captureSavedDetection().getOccurredAt())
                .isEqualTo(LocalDateTime.of(2026, 10, 9, 20, 0));
    }

    @Test
    @DisplayName("규칙의 위험도를 알 수 없으면 UNKNOWN으로 저장한다")
    void unknownSeverity_isNotAssumedToBeCritical() throws Exception {
        ObjectNode json = (ObjectNode) objectMapper.readTree(VALID_JSON);
        ObjectNode rule = (ObjectNode) json.get("matched_rules").get(0);
        rule.remove("severity");

        writer.saveNewDetection(
                objectMapper.treeToValue(json, WafDetectionEventDto.class)
        );

        assertThat(
                captureSavedDetection().getDetectedThreat().getSeverity()
        ).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("여러 규칙 중 가장 높은 위험도인 CRITICAL을 저장 대상으로 전달한다")
    void mostSevereRule_isSelected() throws Exception {

        // given: 기존 테스트 JSON을 수정 가능한 객체로 읽는다.
        ObjectNode json = (ObjectNode) objectMapper.readTree(VALID_JSON);

        // 첫 번째 규칙의 severity를 4로 변경한다.
        ObjectNode firstRule = (ObjectNode) json.get("matched_rules").get(0);

        firstRule.put("severity","4");

        // matched_rules 배열에 두 번째 규칙을 추가한다.
        ObjectNode secondRule = json.withArray("matched_rules").addObject();

        secondRule.put("id","942100");
        secondRule.put("severity","2");

        // 수정한 JSON을 Writer가 받는 DTO로 변환한다.
        WafDetectionEventDto event =
                objectMapper.treeToValue(
                        json,
                        WafDetectionEventDto.class
                );

        // when : 실제 Writer의 저장 로직을 실행한다.
        writer.saveNewDetection(event);

        // then: Repository에 전달한 객체를 꺼내 위험도를 확인한다.
        WafDetection saved = captureSavedDetection();

        assertThat(saved.getDetectedThreat().getSeverity()).isEqualTo("CRITICAL");
    }


    private WafDetection captureSavedDetection() {
        ArgumentCaptor<WafDetection> captor =
                ArgumentCaptor.forClass(WafDetection.class);

        verify(wafRepository).saveAndFlush(captor.capture());

        return captor.getValue();
    }
}