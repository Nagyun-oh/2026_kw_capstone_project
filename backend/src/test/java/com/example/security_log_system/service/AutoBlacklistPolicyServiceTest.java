package com.example.security_log_system.service;

import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.entity.WafDetection;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.WafDetectionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AutoBlacklistPolicyServiceTest {

    private static final Long LOG_ID = 1L;
    private static final String REQUEST_ID = "request-test-001";
    private static final String CLIENT_IP = "203.0.113.10";

    @Mock
    private ThreatRepository threatRepository;

    @Mock
    private WafDetectionRepository wafDetectionRepository;

    @Mock
    private BlacklistService blacklistService;

    private AutoBlacklistPolicyService policyService;

    private LogEntry logEntry;
    private DetectedThreat aiThreat;
    private WafDetection wafDetection;

    @BeforeEach
    void setUp() {
        policyService = new AutoBlacklistPolicyService(
                threatRepository,
                wafDetectionRepository,
                blacklistService
        );

        logEntry = createLog(REQUEST_ID, CLIENT_IP);

        aiThreat = DetectedThreat.builder()
                .id(20L)
                .logEntry(logEntry)
                .threatType("AI Detection")
                .severity("CRITICAL")
                .description("AI detected attack")
                .build();

        DetectedThreat wafThreat = DetectedThreat.builder()
                .id(10L)
                .logEntry(logEntry)
                .threatType("WAF Detection")
                .severity("CRITICAL")
                .build();

        wafDetection = WafDetection.builder()
                .requestId(REQUEST_ID)
                .clientIp(CLIENT_IP)
                .detectedThreat(wafThreat)
                .build();
    }

    @Test
    @DisplayName("같은 요청의 WAF·AI 탐지가 모두 있으면 블랙리스트 등록을 요청한다")
    void bothDetections_registerBlacklist() {
        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.of(wafDetection));

        when(threatRepository.findByLogEntry_IdAndThreatType(
                LOG_ID,
                "AI Detection"
        )).thenReturn(Optional.of(aiThreat));

        policyService.evaluate(logEntry);

        ArgumentCaptor<String> reasonCaptor =
                ArgumentCaptor.forClass(String.class);

        verify(blacklistService).addToBlacklist(
                eq(CLIENT_IP),
                reasonCaptor.capture(),
                eq(4),
                same(wafDetection.getDetectedThreat())
        );

        assertThat(reasonCaptor.getValue())
                .contains("WAF·AI 모두 탐지")
                .contains("WAF 위협 #10")
                .contains("AI 위협 #20");
    }

    @Test
    @DisplayName("WAF 탐지만 있고 AI 탐지가 없으면 자동 등록하지 않는다")
    void wafOnly_doesNotRegister() {
        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.of(wafDetection));

        when(threatRepository.findByLogEntry_IdAndThreatType(
                LOG_ID,
                "AI Detection"
        )).thenReturn(Optional.empty());

        policyService.evaluate(logEntry);

        verify(threatRepository)
                .findByLogEntry_IdAndThreatType(
                        LOG_ID,
                        "AI Detection"
                );

        verifyNoInteractions(blacklistService);
    }

    @Test
    @DisplayName("AI 탐지만 있고 해당 요청의 WAF 탐지가 없으면 자동 등록하지 않는다")
    void aiOnly_doesNotRegister() {
        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.empty());

        policyService.evaluate(logEntry);

        verify(wafDetectionRepository)
                .findByRequestId(REQUEST_ID);

        verifyNoInteractions(
                threatRepository,
                blacklistService
        );
    }

    @Test
    @DisplayName("같은 IP라도 다른 요청의 WAF 탐지와 합쳐 자동 등록하지 않는다")
    void differentRequestId_doesNotCombineDetections() {
        WafDetection otherRequestDetection = WafDetection.builder()
                .requestId("request-other")
                .clientIp(CLIENT_IP)
                .build();

        when(wafDetectionRepository.findByRequestId(anyString()))
                .thenAnswer(invocation -> {
                    String requestId = invocation.getArgument(0);

                    return "request-other".equals(requestId)
                            ? Optional.of(otherRequestDetection)
                            : Optional.empty();
                });

        policyService.evaluate(logEntry);

        verify(wafDetectionRepository)
                .findByRequestId(REQUEST_ID);

        verifyNoInteractions(
                threatRepository,
                blacklistService
        );
    }

    @Test
    @DisplayName("WAF가 먼저 도착한 뒤 AI 탐지가 추가되면 자동 등록한다")
    void wafArrivesFirst_registersAfterAiArrives() {
        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.of(wafDetection));

        when(threatRepository.findByLogEntry_IdAndThreatType(
                LOG_ID,
                "AI Detection"
        )).thenReturn(
                Optional.empty(),
                Optional.of(aiThreat)
        );

        // 첫 판단: WAF 기록만 존재
        policyService.evaluate(logEntry);

        verifyNoInteractions(blacklistService);

        // 두 번째 판단: AI 기록까지 저장된 상태
        policyService.evaluate(logEntry);

        verify(blacklistService, times(1))
                .addToBlacklist(
                        eq(CLIENT_IP),
                        anyString(),
                        eq(4),
                        same(wafDetection.getDetectedThreat())
                );
    }

    @Test
    @DisplayName("AI가 먼저 도착한 뒤 WAF 탐지가 추가되면 자동 등록한다")
    void aiArrivesFirst_registersAfterWafArrives() {
        DetectedThreat laterWafThreat = DetectedThreat.builder()
                .id(30L)
                .logEntry(logEntry)
                .threatType("WAF Detection")
                .severity("CRITICAL")
                .build();

        wafDetection = WafDetection.builder()
                .requestId(REQUEST_ID)
                .clientIp(CLIENT_IP)
                .detectedThreat(laterWafThreat)
                .build();

        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(
                        Optional.empty(),
                        Optional.of(wafDetection)
                );

        when(threatRepository.findByLogEntry_IdAndThreatType(
                LOG_ID,
                "AI Detection"
        )).thenReturn(Optional.of(aiThreat));

        // 첫 판단: 아직 WAF 기록이 없음
        policyService.evaluate(logEntry);

        verifyNoInteractions(blacklistService);

        // 두 번째 판단: WAF 기록까지 저장된 상태
        policyService.evaluate(logEntry);

        verify(blacklistService, times(1))
                .addToBlacklist(
                        eq(CLIENT_IP),
                        anyString(),
                        eq(4),
                        same(aiThreat)
                );
    }

    @Test
    @DisplayName("같은 요청이라도 원본 로그와 WAF의 IP가 다르면 자동 등록하지 않는다")
    void clientIpMismatch_doesNotRegister() {
        WafDetection mismatchedDetection = WafDetection.builder()
                .requestId(REQUEST_ID)
                .clientIp("203.0.113.99")
                .build();

        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.of(mismatchedDetection));

        policyService.evaluate(logEntry);

        verifyNoInteractions(
                threatRepository,
                blacklistService
        );
    }

    @Test
    @DisplayName("원본 로그가 없으면 자동 등록하지 않는다")
    void nullLog_doesNotRegister() {
        policyService.evaluate(null);

        verifyNoInteractions(
                wafDetectionRepository,
                threatRepository,
                blacklistService
        );
    }

    @Test
    @DisplayName("저장되지 않은 원본 로그는 자동 등록하지 않는다")
    void unsavedLog_doesNotRegister() {
        LogEntry unsavedLog = LogEntry.builder()
                .requestId(REQUEST_ID)
                .ipAddress(CLIENT_IP)
                .build();

        policyService.evaluate(unsavedLog);

        verifyNoInteractions(
                wafDetectionRepository,
                threatRepository,
                blacklistService
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   "})
    @DisplayName("requestId가 없거나 공백이면 자동 등록하지 않는다")
    void missingRequestId_doesNotRegister(String requestId) {
        LogEntry entry = createLog(requestId, CLIENT_IP);

        policyService.evaluate(entry);

        verifyNoInteractions(
                wafDetectionRepository,
                threatRepository,
                blacklistService
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "0.0.0.0"})
    @DisplayName("클라이언트 IP가 없거나 정상 판정용 값이면 자동 등록하지 않는다")
    void missingClientIp_doesNotRegister(String clientIp) {
        LogEntry entry = createLog(REQUEST_ID, clientIp);

        policyService.evaluate(entry);

        verifyNoInteractions(
                wafDetectionRepository,
                threatRepository,
                blacklistService
        );
    }

    @Test
    @DisplayName("블랙리스트 저장 오류를 숨기지 않고 호출자에게 전파한다")
    void blacklistFailure_isPropagated() {
        when(wafDetectionRepository.findByRequestId(REQUEST_ID))
                .thenReturn(Optional.of(wafDetection));

        when(threatRepository.findByLogEntry_IdAndThreatType(
                LOG_ID,
                "AI Detection"
        )).thenReturn(Optional.of(aiThreat));

        DataAccessResourceFailureException failure =
                new DataAccessResourceFailureException(
                        "Database unavailable"
                );

        when(blacklistService.addToBlacklist(
                eq(CLIENT_IP),
                anyString(),
                eq(4),
                same(wafDetection.getDetectedThreat())
        )).thenThrow(failure);

        assertThatThrownBy(() -> policyService.evaluate(logEntry))
                .isSameAs(failure);
    }

    private LogEntry createLog(
            String requestId,
            String clientIp
    ) {
        return LogEntry.builder()
                .id(LOG_ID)
                .requestId(requestId)
                .ipAddress(clientIp)
                .build();
    }
}