package com.example.security_log_system.service;


import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.dto.ThreatDto;
import com.example.security_log_system.dto.ThreatResponseDto;
import com.example.security_log_system.dto.ThreatSearchCondition;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.repository.BlacklistRepository;
import com.example.security_log_system.repository.LogRepository;
import com.example.security_log_system.repository.ThreatRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.apache.juli.logging.Log;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class ThreatServiceTest {

    @Mock
    private LogRepository logRepository;

    @Mock
    private ThreatRepository threatRepository;

    @Mock
    private BlacklistService blacklistService;

    @Mock
    private NotificationService notificationService;

    private MeterRegistry meterRegistry;

    private ThreatService threatService;

    @BeforeEach
    void setUp(){
        meterRegistry = new SimpleMeterRegistry();

        threatService = new ThreatService(
                logRepository,
                threatRepository,
                blacklistService,
                notificationService,
                meterRegistry
        );
    }

    @Test
    @DisplayName("검색 조건으로 위협을 조회하고 Entity Page를 DTO Page로 변환한다.")
    void getAllThreats_thenReturnDtoPage(){

        // given
        ThreatSearchCondition condition = new ThreatSearchCondition();
        condition.setThreatType("SQL injection");
        condition.setSeverity("CRITICAL");

        Pageable pageable = PageRequest.of(0,20);

        DetectedThreat threat = DetectedThreat.builder()
                .id(1L)
                .threatType("SQL injection")
                .severity("CRITICAL")
                .description("Suspicious query")
                .detectedAt(LocalDateTime.now())
                .build();

        Page<DetectedThreat> page = new PageImpl<>(List.of(threat),pageable,1);

        // when
        when(threatRepository.findAll(
                any(Specification.class),
                eq(pageable)
        )).thenReturn(page);

        // then
        Page<ThreatResponseDto> result = threatService.getThreats(condition,pageable);

        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getContent().get(0).getThreatType()).isEqualTo("SQL injection");
        assertThat(result.getContent().get(0).getSeverity()).isEqualTo("CRITICAL");

        verify(threatRepository).findAll(
                any(Specification.class),
                eq(pageable)
        );

    }

    @Test
    @DisplayName("dangerLevel 3이면, Threat만 저장하고 blacklist 등록은 안한다.")
    void saveDetectedThreat_whenDangerLevelIsThree_thenSaveThreatOnly(){

        // given
        ThreatDto dto = threatDto(
                "SQL_INJECTION",
                "192.168.0.10",
                3,
                "Suspicious query"
        );

        // when
        threatService.saveDetectedThreat(dto);

        ArgumentCaptor<DetectedThreat> captor = ArgumentCaptor.forClass(DetectedThreat.class);

        // then
        verify(threatRepository).save(captor.capture());

        DetectedThreat saved = captor.getValue();

        assertThat(saved.getThreatType()).isEqualTo("SQL_INJECTION");
        assertThat(saved.getSeverity()).isEqualTo("HIGH");
        assertThat(saved.getDescription()).isEqualTo("Suspicious query");

        assertThat(meterRegistry.counter(
                "security.threats.detected",
                "severity",
                "HIGH"
                ).count()).isEqualTo(1.0);

        verifyNoInteractions(blacklistService);
        verifyNoInteractions(notificationService);
    }

    @Test
    @DisplayName("dangerLevel 4이상이면, Threat 저장 + blacklist 등록 + 긴급 알림 전송")
    void saveDetectedThreat_whenDangerLevelIsFour_thenSaveThreatAndBlacklist(){

        // given
        ThreatDto dto = threatDto(
                "BRUTE_FORCE",
                "192.168.0.10",
                4,
                "Repeated_attack"
        );

        // 저장소가 반환할 위협 객체 설정
        DetectedThreat savedThreat = DetectedThreat.builder()
                .id(10L)
                .build();

        when(threatRepository.save(any(DetectedThreat.class)))
                .thenReturn(savedThreat);

        // when
        threatService.saveDetectedThreat(dto);

        // then
        verify(threatRepository).save(any(DetectedThreat.class));

        assertThat(meterRegistry.counter(
                "security.threats.detected",
                "severity",
                "CRITICAL"
        ).count()).isEqualTo(1.0);

        verify(blacklistService).addToBlacklist(
                eq("192.168.0.10"),
                contains("BRUTE_FORCE"),
                eq(4),
                same(savedThreat)
        );
        verify(notificationService).sendUrgentAlert(
                eq("192.168.0.10"),
                anyString(),
                eq(4)
        );

    }

    @Test
    @DisplayName("AI 응답 logId가 null 이면 예외 발생")
    void saveAiDetectedThreat_whenLogIdIsNull_thenThrowException(){

        // given
        AiResponseDto aiResponseDto = aiResponseDto(null, 0.9f, "192.168.0.10", "AI detected");

        // when
        assertThatThrownBy(() -> threatService.saveAiDetectedThreat(aiResponseDto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("AI response logId is null");

        // then
        verifyNoInteractions(logRepository);
        verifyNoInteractions(threatRepository);
    }

    @Test
    @DisplayName("AI 응답 logId에 해당하는 로그가 없으면 예외 발생")
    void saveAiDetectedThreat_whenLogEntryNotFound_thenThrowException(){

        // given
        AiResponseDto aiResponseDto = aiResponseDto(1L,0.9f,"192.168.0.10","AI detected");

        // when
        when(logRepository.findById(1L)).thenReturn(Optional.empty());

        // then
        assertThatThrownBy(() -> threatService.saveAiDetectedThreat(aiResponseDto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("LogEntry not found");
        assertThat(meterRegistry.find("security.threats.detected").counter())
                .isNull();

        verify(logRepository).findById(1L);
        verifyNoInteractions(threatRepository);
    }

    @Test
    @DisplayName(" AI score가 0.8 이상이면 CRITICAL 저장 + blacklist 등록")
    void saveAiDetectedThreat_whenCriticalScore_thenSaveAndBlacklist(){

        // given
        LogEntry logEntry = LogEntry.builder()
                .id(1L)
                .ipAddress("192.168.0.10")
                .build();

        AiResponseDto aiResponseDto = aiResponseDto(1L, 0.9f, "192.168.0.10", "AI detected");

        // 저장소가 반환할 위협 객체 설정
        DetectedThreat savedThreat = DetectedThreat.builder()
                .id(10L)
                .build();

        when(threatRepository.save(any(DetectedThreat.class)))
                .thenReturn(savedThreat);

        // when
        when(logRepository.findById(1L)).thenReturn(Optional.of(logEntry));

        threatService.saveAiDetectedThreat(aiResponseDto);

        ArgumentCaptor<DetectedThreat> captor = ArgumentCaptor.forClass(DetectedThreat.class);

        verify(threatRepository).save(captor.capture());

        // then
        DetectedThreat saved = captor.getValue();
        assertThat(saved.getLogEntry()).isEqualTo(logEntry);
        assertThat(saved.getThreatType()).isEqualTo("AI Detection");
        assertThat(saved.getSeverity()).isEqualTo("CRITICAL");
        assertThat(saved.getDescription()).isEqualTo("AI detected");
        assertThat(saved.getDetectedAt()).isNotNull();

        assertThat(meterRegistry.counter(
                "security.threats.detected",
                "severity",
                "CRITICAL"
        ).count()).isEqualTo(1.0);

        verify(blacklistService).addToBlacklist(
                eq("192.168.0.10"),
                eq("AI detected"),
                eq(4),
                same(savedThreat)
        );

        verify(notificationService).sendUrgentAlert(
                "192.168.0.10",
                "AI Detection",
                4
        );
    }

    @Test
    @DisplayName("AI score가 0.8 미만이면 HIGH 저장 + blacklist 등록 안함")
    void saveAiDetectedThreat_whenHighScore_thenSavedWithoutBlacklist(){

        // given
        LogEntry logEntry = LogEntry.builder()
                .id(1L)
                .ipAddress("192.168.0.10")
                .build();
        AiResponseDto aiResponseDto = aiResponseDto(1L, 0.7f, "192.168.0.10", "AI detected");

        // when
        when(logRepository.findById(1L)).thenReturn(Optional.of(logEntry));
        threatService.saveAiDetectedThreat(aiResponseDto);

        ArgumentCaptor<DetectedThreat> captor = ArgumentCaptor.forClass(DetectedThreat.class);

        verify(threatRepository).save(captor.capture());

        DetectedThreat saved = captor.getValue();

        // then
        assertThat(saved.getSeverity()).isEqualTo("HIGH");

        assertThat(meterRegistry.counter(
                "security.threats.detected",
                "severity",
                "HIGH"
        ).count()).isEqualTo(1.0);

        verifyNoInteractions(blacklistService);
        verifyNoInteractions(notificationService);
    }

    @Test
    @DisplayName("AI 응답 IP가 0.0.0.0이면 아무 작업도 하지 않는다.")
    void saveAiDetectedThreat_whenIpIsDefault_thenDoNothingAfterLogLookup() {

        // given
        LogEntry logEntry = LogEntry.builder()
                .id(1L)
                .build();
        AiResponseDto aiResponseDto = aiResponseDto(1L,0.9f,"0.0.0.0","AI detected");

        // when
        when(logRepository.findById(1L)).thenReturn(Optional.of(logEntry));
        threatService.saveAiDetectedThreat(aiResponseDto);

        // then
        assertThat(meterRegistry.find("security.threats.detected").counter())
                .isNull();

        verify(logRepository).findById(1L);
        verifyNoInteractions(threatRepository);
        verifyNoInteractions(blacklistService);
        verifyNoInteractions(notificationService);
    }

    // DTO는 데이터 전송 객체이므로, 읽기 전용 및 무상태로 설계되었다.
    // 해당 테스트에서는 임의의 Setter 메서드가 필요하므로 생성하여 사용한다.
    private ThreatDto threatDto( String threatType, String clientIp, int dangerLevel,String description){

        ThreatDto dto = new ThreatDto();

        ReflectionTestUtils.setField(dto,"threatType",threatType);
        ReflectionTestUtils.setField(dto,"clientIp",clientIp);
        ReflectionTestUtils.setField(dto,"dangerLevel",dangerLevel);
        ReflectionTestUtils.setField(dto,"description",description);

        return dto;
    }
    private AiResponseDto aiResponseDto(Long logId, float threatScore, String ipAddress, String reason){

        AiResponseDto dto = new AiResponseDto();

        ReflectionTestUtils.setField(dto,"logId",logId);
        ReflectionTestUtils.setField(dto,"threatScore",threatScore);
        ReflectionTestUtils.setField(dto,"ipAddress",ipAddress);
        ReflectionTestUtils.setField(dto,"reason",reason);

        return dto;

    }
}


/*
테스트:
    1. 검색 조건으로 위협을 조회하고 Entity Page를 DTO Page로 변환한다.
    2. dangerLevel 3이면, Threat만 저장하고 blacklist 등록은 안한다.
    3. dangerLevel 4이상이면, Threat 저장 + blacklist 등록 + 긴급 알림 전송
    4. AI 응답 logId가 null 이면 예외 발생
    5. AI 응답 logId에 해당하는 로그가 없으면 예외 발생
    6. AI score가 0.8 이상이면 CRITICAL 저장 + blacklist 등록
    7. AI score가 0.8 미만이면 HIGH 저장 + blacklist 등록 안함
    8. AI 응답 IP가 0.0.0.0이면 아무 작업도 하지 않는다.
*/



