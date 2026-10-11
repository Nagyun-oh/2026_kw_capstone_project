package com.example.security_log_system.service;

import com.example.security_log_system.dto.AiResponseDto;
import com.example.security_log_system.dto.ThreatDto;
import com.example.security_log_system.dto.ThreatResponseDto;
import com.example.security_log_system.dto.ThreatSearchCondition;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.repository.LogRepository;
import com.example.security_log_system.repository.ThreatRepository;
import com.example.security_log_system.repository.ThreatSpecification;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.security_log_system.util.UtcDateTime;

import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class ThreatService {

    private final LogRepository logRepository;
    private final ThreatRepository threatRepository;
    private final BlacklistService blacklistService;
    private final NotificationService notificationService;
    private final MeterRegistry meterRegistry;

    @Transactional(readOnly = true)
    public Page<ThreatResponseDto> getThreats(ThreatSearchCondition condition, Pageable pageable){
        return threatRepository.findAll(ThreatSpecification.search(condition),pageable)
                .map(ThreatResponseDto::from);
    }


    // HTTP 보조 API를 통해 전달된 위협 저장
    public void saveDetectedThreat(ThreatDto threatDto) {

        DetectedThreat threat = DetectedThreat.builder()
                .threatType(threatDto.getThreatType())
                .severity(mapRiskLevelToSeverity(threatDto.getDangerLevel()))
                .description(threatDto.getDescription())
                .detectedAt(UtcDateTime.now())
                .build();

        DetectedThreat savedThreat = threatRepository.save(threat);

        incrementThreatDetectedMetric(threat.getSeverity());

        log.info("Threat recorded through HTTP endpoint. type={},severity={}",
                threat.getThreatType(),
                threat.getSeverity()
        );

        // 위험도가 높으면 자동으로 블랙리스트 등록
        if (threatDto.getDangerLevel() >= 4) {
            blacklistService.addToBlacklist(threatDto.getClientIp(), " [API 수동 테스트]" + threatDto.getThreatType()
                    , threatDto.getDangerLevel(),savedThreat);

            notificationService.sendUrgentAlert(threatDto.getClientIp(),"[API 수동 테스트]",threatDto.getDangerLevel());
            log.warn("Critical threat added to blacklist. type={}, dangerLevel={}",
                    threat.getThreatType(),
                    threat.getSeverity()
            );
        }
    }

    // Kafka AI 분석 결과를 기반으로 위협 저장
    public void saveAiDetectedThreat(AiResponseDto aiResponse) {
        if (aiResponse.getLogId() ==null){
            throw new IllegalArgumentException("AI response logId is null");
        }

        LogEntry entry = logRepository.findById(aiResponse.getLogId())
                .orElseThrow(() -> new IllegalArgumentException(
            "LogEntry not found"
        ));

        if("0.0.0.0".equals(aiResponse.getIpAddress())){
            return;
        }

        DetectedThreat threat = DetectedThreat.builder()
                .logEntry(entry)
                .threatType("AI Detection")
                .severity(aiResponse.getThreatScore() >= 0.8 ? "CRITICAL" : "HIGH")
                .description(aiResponse.getReason())
                .detectedAt(UtcDateTime.now())
                .build();

        DetectedThreat savedThreat = threatRepository.save(threat);

        incrementThreatDetectedMetric(threat.getSeverity());

        if(aiResponse.getThreatScore() >= 0.8){
            blacklistService.addToBlacklist(aiResponse.getIpAddress(), aiResponse.getReason(), 4,savedThreat);
            notificationService.sendUrgentAlert(aiResponse.getIpAddress(), "AI Detection",4);
        }
    }

    private void incrementThreatDetectedMetric(String severity){
        Counter.builder("security.threats.detected")
                .description("Number of detected security threats")
                .tag("severity",severity)
                .register(meterRegistry)
                .increment();
    }

    // 위험도 숫자를 (1~5) 를 "HIGH", "CRITICAL" 등의 문자열로 바꿔주는 편의 메서드
    private String mapRiskLevelToSeverity(int level) {
        if (level >= 4) return "CRITICAL";
        if (level >= 3) return "HIGH";
        return "MEDIUM";
    }

}

