package com.example.security_log_system.service;

import com.example.security_log_system.dto.WafDetectionDetailDto;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.WafDetectionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class WafDetectionQueryServiceTest {

    private static final String RULES_JSON = """
            [
              {
                "id": "942100",
                "message": "SQL Injection detected",
                "severity": "2",
                "matched_variable": null,
                "attack_types": ["attack-sqli"]
              }
            ]
            """;

    @Mock
    private WafDetectionRepository repository;

    private WafDetectionQueryService service;

    @BeforeEach
    void setUp() {
        service = new WafDetectionQueryService(repository, new ObjectMapper());
    }

    @Test
    @DisplayName("원본 로그가 없어도 WAF 상세와 규칙 근거를 반환한다")
    void detailWithoutAccessLog_isReturned(){
        when(repository.findByDetectedThreat_Id(39L))
                .thenReturn(Optional.of(createDetection(RULES_JSON)));

        WafDetectionDetailDto result =
                service.getDetail(39L).orElseThrow();

        assertThat(result.id()).isEqualTo(1L);
        assertThat(result.threatId()).isEqualTo(39L);
        assertThat(result.logId()).isNull();
        assertThat(result.requestId()).isEqualTo("waf-request-001");

        assertThat(result.occurredAt()).isEqualTo(
                OffsetDateTime.parse("2026-10-12T11:24:32Z")
        );

        assertThat(result.matchedRules()).hasSize(1);
        assertThat(result.matchedRules().get(0).id())
                .isEqualTo("942100");
        assertThat(result.matchedRules().get(0).attackTypes())
                .containsExactly("attack-sqli");
        assertThat(result.matchedRules().get(0).matchedVariable())
                .isNull();

    }

    @Test
    @DisplayName("해당 위협에 WAF 상세가 없으면 빈 결과를 반환한다")
    void missingDetail_returnsEmpty(){
        when(repository.findByDetectedThreat_Id(999L))
                .thenReturn(Optional.empty());

        assertThat(service.getDetail(999L)).isEmpty();
    }

    @Test
    @DisplayName("손상된 규칙 JSON을 정상적인 빈 목록으로 숨기지 않는다")
    void corruptedRules_propagateFailure(){
        when(repository.findByDetectedThreat_Id(39L))
                .thenReturn(Optional.of(createDetection("not-json")));

        assertThatThrownBy(() -> service.getDetail(39L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Stored WAF rules could not be read.");
    }

    private WafDetection createDetection(String rulesJson){
        DetectedThreat threat = DetectedThreat.builder()
                .id(39L)
                .threatType("WAF Detection")
                .severity("CRITICAL")
                .description("WAF 규칙 1건 일치")
                .logEntry(null)
                .build();

        return WafDetection.builder()
                .id(1L)
                .detectedThreat(threat)
                .requestId("waf-request-001")
                .clientIp("203.0.113.10")
                .requestMethod("POST")
                .requestPath("/rest/user/login")
                .responseStatus(200)
                .anomalyScore(5)
                .matchedRulesJson(rulesJson)
                .eventTimeRaw("Mon Oct 12 11:24:32 2026")
                .occurredAt(LocalDateTime.of(2026,10,12,11,24,32))
                .receivedAt(LocalDateTime.of(2026,10,12,11,24,33))
                .build();
    }
}
